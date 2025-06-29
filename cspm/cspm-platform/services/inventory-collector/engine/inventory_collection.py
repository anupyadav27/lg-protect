import boto3
import pandas as pd
import json
import os
import re
import subprocess
import threading
from datetime import datetime
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from botocore.config import Config
from pathlib import Path
from collections import defaultdict
import threading


# ---------- Configuration ----------
# Get the directory where the current script is located
SCRIPT_DIR = Path(__file__).resolve().parent

# Define file paths relative to the script's location
REGION_AVAILABILITY_FILE = SCRIPT_DIR / "aws service region wise.xlsx"
SERVICE_FUNCTION_FILE = SCRIPT_DIR / "Service and function.xlsx"
OUTPUT_DIR = SCRIPT_DIR / "Inventory"

# Create output directory if it doesn't exist
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# Lock for shared counter
lock = threading.Lock()

# Keeps track of how many times a service has been seen per account
service_counts = defaultdict(lambda: defaultdict(int))

# ---------- Session Management ----------
class AWSSessionManager:
    def __init__(self):
        self.session = None
        self.account_id = None
        
    def initialize_session(self, access_key=None, secret_key=None):
        if access_key and secret_key:
            self.session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key
            )
        else:
            self.session = boto3.Session()
        
        try:
            sts = self.session.client('sts')
            self.account_id = sts.get_caller_identity()['Account']
            print(f"✅ Connected to AWS Account: {self.account_id}")
            return True
        except Exception as e:
            print(f"❌ Failed to authenticate with AWS: {str(e)}")
            return False

AWS_SESSION = AWSSessionManager()

# ---------- Global Services ----------
GLOBAL_SERVICES = {
    'organizations': 'aws-global',
    'route53': 'aws-global',
    'iam': 'aws-global',
    'cloudfront': 'us-east-1',
    'waf': 'us-east-1'
}

# ---------- Error Tracking ----------
class ErrorTracker:
    def __init__(self):
        self.function_errors = set()
        self.param_errors = set()
        self.lock = threading.Lock()
    
    def add_function_error(self, service, function):
        with self.lock:
            self.function_errors.add((service, function))
    
    def has_function_error(self, service, function):
        with self.lock:
            return (service, function) in self.function_errors
    
    def add_param_error(self, service, function, param):
        with self.lock:
            self.param_errors.add((service, function, param))
    
    def has_param_error(self, service, function, param):
        with self.lock:
            return (service, function, param) in self.param_errors

GLOBAL_ERROR_TRACKER = ErrorTracker()

# ---------- Client Management ----------
def get_client(service, region=None, session=None):
    if not session:
        session = AWS_SESSION.session
        
    if service in GLOBAL_SERVICES:
        region = GLOBAL_SERVICES[service]
    
    config = Config(
        retries={
            'max_attempts': 3,
            'mode': 'adaptive'
        }
    )
    
    return session.client(service, region_name=region, config=config)

def resolve_codeartifact_domain(client):
    try:
        # First try to list existing domains
        response = client.list_domains()
        if response.get('domains'):
            return response['domains'][0]['name']
            
        # If no domains exist, try to create one
        try:
            domain_name = "default-compliance-domain"
            client.create_domain(
                domain=domain_name,
                tags=[{'Key': 'CreatedBy', 'Value': 'ComplianceScript'}]
            )
            return domain_name
        except Exception as create_error:
            print(f"[!] Could not create CodeArtifact domain: {str(create_error)}")
            return "default-compliance-domain"  # Fallback value
            
    except Exception as e:
        print(f"[!] Error resolving CodeArtifact domain: {str(e)}")
        return "default-compliance-domain"  # Fallback value



# ---------- Parameter Resolution ----------
def resolve_param(service, function_name, param, region):
    try:
        # First check service-specific resolvers
        resolvers = {
            "route53": {
                "ResourceType": lambda _: "hostedzone",
                "ResourceId": lambda c: c.list_hosted_zones().get("HostedZones", [{}])[0].get("Id", "/hostedzone/EXAMPLE")
            },
            "codeartifact": {
                "domain": lambda c: resolve_codeartifact_domain(c),
                "repository": lambda c: (
                    c.list_repositories().get("repositories", [{}])[0].get("name")
                    if c.list_repositories().get("repositories")
                    else "example-repository"
                )
            },
            "cloudfront": {
                "Resource": lambda c: c.list_distributions().get("DistributionList", {}).get("Items", [{}])[0].get("ARN", f"arn:aws:cloudfront::{AWS_SESSION.account_id}:distribution/EXAMPLE")
            }
        }
        
        if service in resolvers and param in resolvers[service]:
            client = get_client(service, region)
            return resolvers[service][param](client)
            
        # Fallback to generic resolution
        if param.lower().endswith(('type', 'types')):
            return "example-type"
        elif param.lower().endswith('domain'):
            return "example-domain"
        elif param.lower().endswith('resource'):
            return f"arn:aws:{service}:{region}:{AWS_SESSION.account_id}:example-resource"
            
        return None
        
    except Exception as e:
        print(f"[!] Error resolving {param} for {service}.{function_name}: {str(e)}")
        return None
    
# ---------- Function Execution ----------
def call_function(service, function_name, region):
    try:
        if GLOBAL_ERROR_TRACKER.has_function_error(service, function_name):
            return None

        client = get_client(service, region)
        
        if not hasattr(client, function_name):
            error_msg = f"Function {function_name} not found on boto3 client"
            GLOBAL_ERROR_TRACKER.add_function_error(service, function_name)
            return {"error": error_msg}

        try:
            return getattr(client, function_name)()
        except Exception as e:
            missing = re.findall(r"Missing required parameter(?: in input)?: '?\"?([\w]+)", str(e))
            if missing:
                params = {}
                for p in missing:
                    val = resolve_param(service, function_name, p, region)
                    if val is not None:
                        params[p] = val
                    else:
                        error_msg = f"Missing required parameter: '{p}'"
                        GLOBAL_ERROR_TRACKER.add_function_error(service, function_name)
                        return {"error": error_msg}
                return getattr(client, function_name)(**params)
            
            error_msg = str(e)
            GLOBAL_ERROR_TRACKER.add_function_error(service, function_name)
            return {"error": error_msg}

    except Exception as e:
        error_msg = f"Function execution failed: {str(e)}"
        GLOBAL_ERROR_TRACKER.add_function_error(service, function_name)
        return {"error": error_msg}

# ---------- Main Execution ----------
def main():
    print("🔐 AWS Credentials")
    access_key = input("Enter AWS Access Key (leave empty for default credentials): ").strip()
    secret_key = input("Enter AWS Secret Key (leave empty for default credentials): ").strip()

    if access_key and secret_key:
        if not AWS_SESSION.initialize_session(access_key, secret_key):
            return
    else:
        if not AWS_SESSION.initialize_session():
            return

    print("📄 Loading configuration...")
    valid_services = set(AWS_SESSION.session.get_available_services())
    
    try:
        service_region_map = defaultdict(set)
        df = pd.read_excel(REGION_AVAILABILITY_FILE)
        for _, row in df.iterrows():
            service = str(row[0]).strip().lower()
            region = str(row[1]).strip().lower()
            if service in valid_services and region:
                service_region_map[region].add(service)
    except Exception as e:
        print(f"Error loading region availability file: {str(e)}")
        return

    try:
        service_function_map = defaultdict(list)
        df = pd.read_excel(SERVICE_FUNCTION_FILE)
        for _, row in df.iterrows():
            service = str(row[0]).strip().lower()
            function = str(row[1]).strip()
            if service in valid_services and function:
                service_function_map[service].append(function)
    except Exception as e:
        print(f"Error loading service function file: {str(e)}")
        return

    enabled_regions = get_enabled_regions(AWS_SESSION.session)
    if not enabled_regions:
        print("❌ Failed to fetch enabled regions")
        return

    results, errors = [], []
    lock = threading.Lock()

    print("🚀 Starting compliance checks...")
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = []
        for region in enabled_regions:
            for service in service_region_map.get(region.lower(), set()):
                if service in service_function_map:
                    futures.append(executor.submit(
                        process_region_service, region, service, 
                        service_function_map[service], results, errors, lock
                    ))
        
        for future in as_completed(futures):
            pass  # Progress tracking can be added here

    
    print_summary(results, errors)

def process_region_service(region, service, functions, results, errors, lock):
    for fn in functions:
        if GLOBAL_ERROR_TRACKER.has_function_error(service, fn):
            continue

        output = call_function(service, fn, region)
        if output is None:
            continue

        entry = {
            "region": region,
            "service": service,
            "function": fn,
            "timestamp": datetime.utcnow().isoformat()
        }

        account_id = AWS_SESSION.account_id
        with lock:
            service_counts[account_id][service] += 1
            service_folder_name = service
            if service_counts[account_id][service] > 1:
                service_folder_name = f"{service}_{service_counts[account_id][service]}"

            path = OUTPUT_DIR / account_id / region / service_folder_name / fn
            path.mkdir(parents=True, exist_ok=True)


            timestamp_str = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            output_file_path = path / f"{fn}_output_{timestamp_str}.json"
            try:
                if "error" in output:
                    entry["error"] = output["error"]
                    errors.append(entry)
                    with open(output_file_path.with_suffix(".json"), "w") as f:
                        json.dump(entry, f, indent=2, default=lambda o: o.isoformat() if isinstance(o, datetime) else str(o))

                else:
                    entry["output"] = output
                    results.append(entry)
                    with open(output_file_path.with_suffix(".json"), "w") as f:
                        json.dump(output, f, indent=2, default=lambda o: o.isoformat() if isinstance(o, datetime) else str(o))

            except Exception as e:
                print(f"❌ Failed to write output for {service}.{fn} in {region}: {e}")

def get_enabled_regions(session):
    try:
        ec2 = session.client('ec2', region_name='us-east-1')
        regions = ec2.describe_regions(AllRegions=True)['Regions']
        return [r['RegionName'] for r in regions 
               if r['OptInStatus'] in ('opt-in-not-required', 'opted-in')]
    except Exception as e:
        print(f"Error fetching enabled regions: {str(e)}")
        return []


def print_summary(results, errors):
    print(f"\n📊 Summary:")
    print(f"  - Successful calls: {len(results)}")
    print(f"  - Errors: {len(errors)}")
    
    service_stats = defaultdict(lambda: {'success': 0, 'errors': 0})
    for item in results:
        service_stats[item['service']]['success'] += 1
    for item in errors:
        service_stats[item['service']]['errors'] += 1
    
    print("\n🔍 Service-wise statistics:")
    for service, stats in sorted(service_stats.items()):
        print(f"  - {service}: ✅ {stats['success']} success, ❌ {stats['errors']} errors")

if __name__ == "__main__":
    main()
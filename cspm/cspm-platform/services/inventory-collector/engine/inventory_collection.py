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
            },
            "ssm": {
                "Name": lambda c: get_sample_parameter_name(c),
                "Names": lambda c: get_sample_parameter_names(c),
                "Path": lambda c: "/",
                "ParameterFilters": lambda c: [{"Key": "Type", "Values": ["String"]}],
                "Filters": lambda c: [{"Key": "Name", "Values": ["/aws/"]}],
                "DocumentName": lambda c: get_sample_document_name(c),
                "InstanceId": lambda c: get_sample_instance_id(c, region),
                "ResourceType": lambda c: "ManagedInstance",
                "ResourceId": lambda c: get_sample_instance_id(c, region),
                "CommandId": lambda c: "example-command-id",
                "AssociationId": lambda c: get_sample_association_id(c),
                "InstanceIds": lambda c: [get_sample_instance_id(c, region)],
                "Targets": lambda c: [{"Key": "tag:Environment", "Values": ["production"]}],
                "WindowId": lambda c: get_sample_maintenance_window_id(c),
                "WindowTaskId": lambda c: "example-task-id",
                "SessionId": lambda c: "example-session-id",
                "OpsItemId": lambda c: "oi-1234567890abcdef0",
                "PatchGroup": lambda c: "default",
                "BaselineId": lambda c: get_sample_patch_baseline_id(c)
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

# ---------- SSM Helper Functions ----------
def get_sample_parameter_name(ssm_client):
    """Get a sample parameter name from existing parameters"""
    try:
        response = ssm_client.describe_parameters(MaxResults=1)
        if response.get('Parameters'):
            return response['Parameters'][0]['Name']
        return "/example/parameter"
    except Exception:
        return "/example/parameter"

def get_sample_parameter_names(ssm_client):
    """Get sample parameter names list"""
    try:
        response = ssm_client.describe_parameters(MaxResults=5)
        if response.get('Parameters'):
            return [param['Name'] for param in response['Parameters'][:3]]
        return ["/example/parameter1", "/example/parameter2"]
    except Exception:
        return ["/example/parameter1", "/example/parameter2"]

def get_sample_document_name(ssm_client):
    """Get a sample SSM document name"""
    try:
        response = ssm_client.list_documents(MaxResults=1, Filters=[{"Key": "DocumentType", "Values": ["Command"]}])
        if response.get('DocumentIdentifiers'):
            return response['DocumentIdentifiers'][0]['Name']
        return "AWS-RunShellScript"
    except Exception:
        return "AWS-RunShellScript"

def get_sample_instance_id(ssm_client, region):
    """Get a sample managed instance ID"""
    try:
        response = ssm_client.describe_instance_information(MaxResults=1)
        if response.get('InstanceInformationList'):
            return response['InstanceInformationList'][0]['InstanceId']
        
        # Fallback: try to get EC2 instances
        ec2_client = get_client('ec2', region)
        ec2_response = ec2_client.describe_instances(MaxResults=1)
        for reservation in ec2_response.get('Reservations', []):
            for instance in reservation.get('Instances', []):
                if instance.get('State', {}).get('Name') == 'running':
                    return instance['InstanceId']
        
        return "i-1234567890abcdef0"
    except Exception:
        return "i-1234567890abcdef0"

def get_sample_association_id(ssm_client):
    """Get a sample association ID"""
    try:
        response = ssm_client.list_associations(MaxResults=1)
        if response.get('Associations'):
            return response['Associations'][0]['AssociationId']
        return "12345678-1234-1234-1234-123456789012"
    except Exception:
        return "12345678-1234-1234-1234-123456789012"

def get_sample_maintenance_window_id(ssm_client):
    """Get a sample maintenance window ID"""
    try:
        response = ssm_client.describe_maintenance_windows(MaxResults=1)
        if response.get('WindowIdentities'):
            return response['WindowIdentities'][0]['WindowId']
        return "mw-1234567890abcdef0"
    except Exception:
        return "mw-1234567890abcdef0"

def get_sample_patch_baseline_id(ssm_client):
    """Get a sample patch baseline ID"""
    try:
        response = ssm_client.describe_patch_baselines(MaxResults=1)
        if response.get('BaselineIdentities'):
            return response['BaselineIdentities'][0]['BaselineId']
        return "pb-1234567890abcdef0"
    except Exception:
        return "pb-1234567890abcdef0"

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

# ---------- SSM Parameter Store Security Analysis ----------
class SSMParameterAnalyzer:
    def __init__(self, session):
        self.session = session
        self.security_findings = []
        
    def analyze_parameter_security(self, region):
        """Comprehensive SSM Parameter Store security analysis"""
        try:
            ssm_client = get_client('ssm', region, self.session)
            findings = {
                'region': region,
                'timestamp': datetime.utcnow().isoformat(),
                'parameters': [],
                'security_issues': [],
                'compliance_status': {},
                'recommendations': []
            }
            
            # Get all parameters with pagination
            paginator = ssm_client.get_paginator('describe_parameters')
            
            for page in paginator.paginate():
                for param in page.get('Parameters', []):
                    param_analysis = self._analyze_parameter(ssm_client, param, region)
                    findings['parameters'].append(param_analysis)
                    
                    # Check for security issues
                    security_issues = self._check_parameter_security(param_analysis)
                    findings['security_issues'].extend(security_issues)
            
            # Generate compliance status
            findings['compliance_status'] = self._generate_compliance_status(findings)
            
            # Generate recommendations
            findings['recommendations'] = self._generate_recommendations(findings)
            
            return findings
            
        except Exception as e:
            return {
                'region': region,
                'error': f"Failed to analyze SSM parameters: {str(e)}",
                'timestamp': datetime.utcnow().isoformat()
            }
    
    def _analyze_parameter(self, ssm_client, param, region):
        """Analyze individual parameter for security and compliance"""
        analysis = {
            'name': param['Name'],
            'type': param['Type'],
            'tier': param.get('Tier', 'Standard'),
            'last_modified': param.get('LastModifiedDate', '').isoformat() if param.get('LastModifiedDate') else None,
            'version': param.get('Version', 0),
            'allowed_pattern': param.get('AllowedPattern'),
            'description': param.get('Description', ''),
            'key_id': param.get('KeyId'),
            'policies': param.get('Policies', []),
            'tags': [],
            'security_score': 0,
            'encryption_status': 'unencrypted',
            'access_patterns': [],
            'value_analysis': {}
        }
        
        try:
            # Get parameter tags
            tags_response = ssm_client.list_tags_for_resource(
                ResourceType='Parameter',
                ResourceId=param['Name']
            )
            analysis['tags'] = tags_response.get('TagList', [])
            
            # Analyze encryption
            if param['Type'] == 'SecureString':
                analysis['encryption_status'] = 'encrypted'
                analysis['security_score'] += 30
                
                if param.get('KeyId'):
                    analysis['security_score'] += 20
                    # Check if using customer-managed KMS key
                    if not param['KeyId'].startswith('alias/aws/ssm'):
                        analysis['security_score'] += 10
            
            # Analyze parameter name patterns
            analysis['name_analysis'] = self._analyze_parameter_name(param['Name'])
            analysis['security_score'] += analysis['name_analysis'].get('security_points', 0)
            
            # Get parameter value for analysis (if not encrypted or if we have permissions)
            if param['Type'] != 'SecureString':
                try:
                    value_response = ssm_client.get_parameter(Name=param['Name'])
                    value = value_response['Parameter']['Value']
                    analysis['value_analysis'] = self._analyze_parameter_value(value)
                    analysis['security_score'] += analysis['value_analysis'].get('security_points', 0)
                except Exception:
                    analysis['value_analysis'] = {'error': 'Cannot access parameter value'}
            
            # Check parameter policies
            if analysis['policies']:
                analysis['security_score'] += 15
            
            # Check for proper tagging
            if analysis['tags']:
                analysis['security_score'] += 10
                
            # Check for description
            if analysis['description']:
                analysis['security_score'] += 5
                
        except Exception as e:
            analysis['analysis_error'] = str(e)
        
        return analysis
    
    def _analyze_parameter_name(self, name):
        """Analyze parameter name for security patterns"""
        analysis = {
            'security_points': 0,
            'issues': [],
            'patterns': []
        }
        
        # Check for sensitive data indicators in name
        sensitive_patterns = [
            'password', 'passwd', 'pwd', 'secret', 'key', 'token',
            'credential', 'auth', 'api_key', 'private'
        ]
        
        name_lower = name.lower()
        for pattern in sensitive_patterns:
            if pattern in name_lower:
                analysis['patterns'].append(f"Contains sensitive indicator: {pattern}")
                analysis['security_points'] += 5
        
        # Check for proper naming convention
        if name.startswith('/'):
            analysis['security_points'] += 5
            analysis['patterns'].append("Uses hierarchical naming")
        
        # Check for environment indicators
        env_patterns = ['prod', 'dev', 'test', 'staging']
        for env in env_patterns:
            if env in name_lower:
                analysis['patterns'].append(f"Environment indicator: {env}")
                analysis['security_points'] += 2
        
        return analysis
    
    def _analyze_parameter_value(self, value):
        """Analyze parameter value for potential security issues"""
        analysis = {
            'security_points': 0,
            'issues': [],
            'patterns': []
        }
        
        # Check for potential secrets in plain text
        secret_patterns = [
            (r'AKIA[0-9A-Z]{16}', 'AWS Access Key'),
            (r'[A-Za-z0-9/+=]{40}', 'Potential AWS Secret Key'),
            (r'sk-[a-zA-Z0-9]{48}', 'OpenAI API Key'),
            (r'ghp_[a-zA-Z0-9]{36}', 'GitHub Token'),
            (r'xoxb-[0-9]+-[0-9]+-[a-zA-Z0-9]+', 'Slack Bot Token'),
            (r'[a-zA-Z0-9]{32}', 'Potential MD5 Hash'),
            (r'[a-zA-Z0-9]{64}', 'Potential SHA256 Hash')
        ]
        
        for pattern, description in secret_patterns:
            if re.search(pattern, value):
                analysis['issues'].append(f"Potential {description} detected")
                analysis['security_points'] -= 20  # Negative points for security issues
        
        # Check value length and complexity
        if len(value) > 20:
            analysis['security_points'] += 5
            
        if re.search(r'[A-Z]', value) and re.search(r'[a-z]', value) and re.search(r'[0-9]', value):
            analysis['security_points'] += 5
            analysis['patterns'].append("Complex value pattern")
        
        return analysis
    
    def _check_parameter_security(self, param_analysis):
        """Check for security issues in parameter configuration"""
        issues = []
        
        # Check if sensitive data is not encrypted
        if any(pattern in param_analysis['name'].lower() 
               for pattern in ['password', 'secret', 'key', 'token']):
            if param_analysis['encryption_status'] == 'unencrypted':
                issues.append({
                    'parameter': param_analysis['name'],
                    'severity': 'HIGH',
                    'issue': 'Sensitive parameter not encrypted',
                    'recommendation': 'Use SecureString type for sensitive data'
                })
        
        # Check for missing tags
        if not param_analysis['tags']:
            issues.append({
                'parameter': param_analysis['name'],
                'severity': 'MEDIUM',
                'issue': 'Parameter missing tags',
                'recommendation': 'Add appropriate tags for governance'
            })
        
        # Check for low security score
        if param_analysis['security_score'] < 20:
            issues.append({
                'parameter': param_analysis['name'],
                'severity': 'MEDIUM',
                'issue': 'Low security score',
                'recommendation': 'Review parameter configuration and security practices'
            })
        
        # Check for potential secrets in value
        if param_analysis['value_analysis'].get('issues'):
            for issue in param_analysis['value_analysis']['issues']:
                issues.append({
                    'parameter': param_analysis['name'],
                    'severity': 'CRITICAL',
                    'issue': issue,
                    'recommendation': 'Remove sensitive data and use SecureString'
                })
        
        return issues
    
    def _generate_compliance_status(self, findings):
        """Generate compliance status based on findings"""
        total_params = len(findings['parameters'])
        encrypted_params = sum(1 for p in findings['parameters'] 
                             if p['encryption_status'] == 'encrypted')
        tagged_params = sum(1 for p in findings['parameters'] if p['tags'])
        
        critical_issues = sum(1 for issue in findings['security_issues'] 
                            if issue['severity'] == 'CRITICAL')
        high_issues = sum(1 for issue in findings['security_issues'] 
                         if issue['severity'] == 'HIGH')
        
        compliance_score = 100
        if total_params > 0:
            compliance_score -= (critical_issues * 20)
            compliance_score -= (high_issues * 10)
            compliance_score += (encrypted_params / total_params * 30)
            compliance_score += (tagged_params / total_params * 20)
        
        return {
            'total_parameters': total_params,
            'encrypted_parameters': encrypted_params,
            'tagged_parameters': tagged_params,
            'critical_issues': critical_issues,
            'high_issues': high_issues,
            'compliance_score': max(0, min(100, compliance_score)),
            'encryption_percentage': (encrypted_params / total_params * 100) if total_params > 0 else 0,
            'tagging_percentage': (tagged_params / total_params * 100) if total_params > 0 else 0
        }
    
    def _generate_recommendations(self, findings):
        """Generate security recommendations"""
        recommendations = []
        
        compliance = findings['compliance_status']
        
        if compliance['encryption_percentage'] < 80:
            recommendations.append({
                'priority': 'HIGH',
                'category': 'Encryption',
                'recommendation': 'Increase encryption coverage for sensitive parameters',
                'action': 'Convert String parameters containing sensitive data to SecureString'
            })
        
        if compliance['tagging_percentage'] < 70:
            recommendations.append({
                'priority': 'MEDIUM',
                'category': 'Governance',
                'recommendation': 'Improve parameter tagging for better governance',
                'action': 'Add tags like Environment, Owner, Purpose to all parameters'
            })
        
        if compliance['critical_issues'] > 0:
            recommendations.append({
                'priority': 'CRITICAL',
                'category': 'Security',
                'recommendation': 'Address critical security issues immediately',
                'action': 'Review and remediate all critical security findings'
            })
        
        return recommendations

# Enhanced SSM Parameter Store collection
def collect_ssm_parameters_enhanced(region):
    """Enhanced SSM Parameter Store collection with security analysis"""
    try:
        analyzer = SSMParameterAnalyzer(AWS_SESSION.session)
        findings = analyzer.analyze_parameter_security(region)
        
        # Save detailed analysis
        account_id = AWS_SESSION.account_id
        output_path = OUTPUT_DIR / account_id / region / "ssm_parameter_analysis"
        output_path.mkdir(parents=True, exist_ok=True)
        
        timestamp_str = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        
        # Save security analysis
        security_file = output_path / f"ssm_security_analysis_{timestamp_str}.json"
        with open(security_file, 'w') as f:
            json.dump(findings, f, indent=2, default=str)
        
        # Generate summary report
        summary_file = output_path / f"ssm_compliance_summary_{timestamp_str}.json"
        summary = {
            'region': region,
            'timestamp': findings['timestamp'],
            'compliance_status': findings['compliance_status'],
            'critical_issues_count': len([i for i in findings['security_issues'] if i['severity'] == 'CRITICAL']),
            'high_issues_count': len([i for i in findings['security_issues'] if i['severity'] == 'HIGH']),
            'recommendations_count': len(findings['recommendations']),
            'top_recommendations': findings['recommendations'][:3]
        }
        
        with open(summary_file, 'w') as f:
            json.dump(summary, f, indent=2, default=str)
        
        print(f"✅ SSM Parameter analysis completed for {region}")
        print(f"   - Parameters analyzed: {findings['compliance_status']['total_parameters']}")
        print(f"   - Compliance score: {findings['compliance_status']['compliance_score']:.1f}%")
        print(f"   - Critical issues: {findings['compliance_status']['critical_issues']}")
        
        return findings
        
    except Exception as e:
        error_msg = f"Failed to collect SSM parameters for {region}: {str(e)}"
        print(f"❌ {error_msg}")
        return {"error": error_msg, "region": region}

if __name__ == "__main__":
    main()
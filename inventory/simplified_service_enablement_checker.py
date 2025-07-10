#!/usr/bin/env python3
"""
Enterprise AWS Multi-Account Service Enablement Checker with Enhanced Timestamp Management
Comprehensive service discovery across multiple AWS accounts with advanced error analysis
"""
import boto3
import json
import os
import threading
import time
import uuid
import shutil
from datetime import datetime, timezone
from collections import defaultdict, Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from botocore.config import Config
from botocore.exceptions import ClientError, NoCredentialsError, EndpointConnectionError
from pathlib import Path

# Import the error analyzer for post-scan analysis
try:
    from error_analyzer import run_post_scan_analysis
    ERROR_ANALYZER_AVAILABLE = True
except ImportError:
    ERROR_ANALYZER_AVAILABLE = False
    print("⚠️  Error analyzer not available - post-scan analysis will be skipped")

# ---------- Enterprise Configuration ----------
SCRIPT_DIR = Path(__file__).resolve().parent

# Enhanced threading configuration
MAX_WORKERS = 15  # Increased for enterprise scale
TIMEOUT_SECONDS = 30
MAX_RETRIES = 3

# Thread-safe global statistics
lock = threading.Lock()
scan_stats = {
    "total_api_calls": 0,
    "successful_calls": 0,
    "failed_calls": 0,
    "accounts_processed": 0,
    "regions_processed": 0,
    "services_checked": 0
}

# Global services will be loaded dynamically from service mapping
GLOBAL_SERVICES = {}

# ---------- Service Mapping Loader ----------
def load_service_mapping():
    """Load service mapping and extract global services configuration"""
    global GLOBAL_SERVICES
    
    mapping_file = SCRIPT_DIR / "service_enablement_mapping.json"
    try:
        with open(mapping_file, 'r') as f:
            mapping = json.load(f)
            print(f"✅ Successfully loaded service mapping from {mapping_file.name}")
            
            # Extract global services and their default regions
            GLOBAL_SERVICES = {}
            for service_name, config in mapping.items():
                if config.get('scope') == 'global':
                    # Global services default to us-east-1
                    GLOBAL_SERVICES[service_name] = 'us-east-1'
            
            print(f"📋 Identified {len(GLOBAL_SERVICES)} global services: {', '.join(GLOBAL_SERVICES.keys())}")
            print(f"📋 Regional services: {len(mapping) - len(GLOBAL_SERVICES)}")
            
            return mapping
            
    except FileNotFoundError:
        print(f"❌ Service mapping file not found: {mapping_file}")
        print(f"💡 Please ensure service_enablement_mapping.json exists in the inventory directory")
        raise FileNotFoundError(f"Required service mapping file not found: {mapping_file}")
    except json.JSONDecodeError as e:
        print(f"❌ Invalid JSON in service mapping file: {e}")
        print(f"💡 Please check the JSON syntax in {mapping_file}")
        raise
    except Exception as e:
        print(f"❌ Error loading service mapping: {e}")
        raise

# ---------- Enterprise AWS Account Manager ----------
class EnterpriseAccountManager:
    """Advanced multi-account AWS management with credential validation"""
    def __init__(self):
        self.accounts = []
        self.account_cache = {}
        
    def add_account(self, name, access_key=None, secret_key=None, session_token=None, 
                   profile=None, role_arn=None, external_id=None):
        """Add an AWS account with multiple authentication methods"""
        try:
            # Create session based on authentication method
            if profile:
                session = boto3.Session(profile_name=profile)
            elif role_arn:
                session = self._assume_role_session(role_arn, external_id, access_key, secret_key)
            elif access_key and secret_key:
                session = boto3.Session(
                    aws_access_key_id=access_key,
                    aws_secret_access_key=secret_key,
                    aws_session_token=session_token
                )
            else:
                session = boto3.Session()

            # Validate credentials and get account info
            sts = session.client('sts')
            identity = sts.get_caller_identity()
            account_id = identity['Account']
            user_arn = identity.get('Arn', 'Unknown')
            
            # Get enabled regions with caching
            if account_id not in self.account_cache:
                enabled_regions = self._get_enabled_regions(session)
                self.account_cache[account_id] = enabled_regions
            else:
                enabled_regions = self.account_cache[account_id]
            
            account_info = {
                'name': name,
                'account_id': account_id,
                'user_arn': user_arn,
                'session': session,
                'enabled_regions': enabled_regions,
                'auth_method': 'profile' if profile else 'role' if role_arn else 'keys' if access_key else 'default',
                'added_at': datetime.now(timezone.utc).isoformat()
            }
            
            self.accounts.append(account_info)
            print(f"✅ Added account: {name} ({account_id}) with {len(enabled_regions)} regions via {account_info['auth_method']}")
            return True
            
        except Exception as e:
            print(f"❌ Failed to add account {name}: {str(e)}")
            return False
    
    def _assume_role_session(self, role_arn, external_id, access_key=None, secret_key=None):
        """Create session by assuming IAM role"""
        if access_key and secret_key:
            base_session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key
            )
        else:
            base_session = boto3.Session()
        
        sts = base_session.client('sts')
        assume_role_kwargs = {
            'RoleArn': role_arn,
            'RoleSessionName': f'ServiceEnablementScan-{int(time.time())}'
        }
        
        if external_id:
            assume_role_kwargs['ExternalId'] = external_id
        
        response = sts.assume_role(**assume_role_kwargs)
        credentials = response['Credentials']
        
        return boto3.Session(
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken']
        )
    
    def _get_enabled_regions(self, session):
        """Get enabled regions with enhanced error handling"""
        try:
            ec2 = session.client('ec2', region_name='us-east-1')
            regions_response = ec2.describe_regions(AllRegions=True)
            enabled_regions = [
                r['RegionName'] for r in regions_response['Regions'] 
                if r['OptInStatus'] in ('opt-in-not-required', 'opted-in')
            ]
            return sorted(enabled_regions)
        except Exception as e:
            print(f"⚠️  Could not fetch enabled regions: {str(e)}")
            # Return comprehensive fallback list
            return [
                'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
                'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-central-1', 'eu-north-1',
                'ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1', 'ap-northeast-2', 'ap-northeast-3',
                'ap-south-1', 'ca-central-1', 'sa-east-1'
            ]
    
    def get_total_scan_scope(self):
        """Calculate total scan scope for progress tracking"""
        total_regions = sum(len(account['enabled_regions']) for account in self.accounts)
        return len(self.accounts), total_regions

# ---------- Enhanced Error Collection System ----------
class EnterpriseErrorLogger:
    """Enterprise-grade error logging with advanced analytics"""
    def __init__(self, scan_session_id):
        self.scan_session_id = scan_session_id
        self.errors = []
        self.error_categories = Counter()
        self.service_errors = defaultdict(Counter)
        self.region_errors = defaultdict(Counter)
        self.account_errors = defaultdict(Counter)
        self.temporal_errors = defaultdict(list)
        self.lock = threading.Lock()
    
    def log_error(self, account_id, region, service, function, error_type, error_message):
        """Log error with comprehensive metadata"""
        with self.lock:
            error_record = {
                'Account': account_id,
                'Region': region,
                'Service': service,
                'Function': function,
                'ErrorType': error_type,
                'ErrorMessage': str(error_message),
                'Timestamp': datetime.now(timezone.utc).isoformat(),
                'ScanSessionId': self.scan_session_id
            }
            
            self.errors.append(error_record)
            self.error_categories[error_type] += 1
            self.service_errors[service][error_type] += 1
            self.region_errors[region][error_type] += 1
            self.account_errors[account_id][error_type] += 1
            
            # Temporal tracking
            hour_key = datetime.now().strftime('%Y-%m-%d-%H')
            self.temporal_errors[hour_key].append(error_record)
    
    def categorize_error(self, error):
        """Advanced error categorization"""
        error_str = str(error).lower()
        
        if isinstance(error, ClientError):
            error_code = error.response.get('Error', {}).get('Code', '')
            
            # Access/Permission errors
            if any(code in error_code for code in ['AccessDenied', 'UnauthorizedOperation', 'Forbidden']):
                return 'access_denied'
            # Service enablement/subscription
            elif any(code in error_code for code in ['SubscriptionRequiredException', 'NotSubscribed', 'OptInRequired']):
                return 'service_not_enabled'
            # Parameter validation
            elif any(code in error_code for code in ['ValidationException', 'InvalidParameterValue', 'MissingParameter']):
                return 'parameter_validation'
            # Service unavailable
            elif any(code in error_code for code in ['ServiceUnavailable', 'Throttling', 'RequestLimitExceeded']):
                return 'service_unavailable'
            # Resource not found
            elif any(code in error_code for code in ['ResourceNotFoundException', 'NoSuchEntity']):
                return 'resource_not_found'
            # Unsupported operation
            elif any(code in error_code for code in ['InvalidAction', 'UnsupportedOperation']):
                return 'unsupported_operation'
        
        # Connection errors
        elif isinstance(error, EndpointConnectionError):
            return 'endpoint_connection_error'
        elif isinstance(error, NoCredentialsError):
            return 'credentials_error'
        # Parameter validation from boto3
        elif 'parameter validation failed' in error_str:
            return 'parameter_validation'
        # Function not found
        elif 'not found on' in error_str and 'client' in error_str:
            return 'function_not_found'
        # Timeout
        elif any(term in error_str for term in ['timeout', 'timed out']):
            return 'timeout'
        
        return 'unknown'

# ---------- Enhanced Summary Report Generator ----------
def generate_enhanced_summary_report(results, accounts, scan_session_id, scan_start_time, scan_duration, scan_stats, error_logger):
    """Generate enhanced summary report with Account → Region/Global → Services → Resource Identifiers hierarchy"""
    
    # Initialize the new hierarchical structure: Account → Region/Global → Services → Resources
    account_centric_report = {}
    
    # Process each result to build the hierarchical structure
    for result in results:
        account_id = result['account_id']
        account_name = result.get('account_name', account_id)
        region = result['region']
        service = result['service']
        enabled = result['enabled']
        resource_count = result.get('resource_count', 0)
        resources = result.get('resources', [])
        scope = result.get('scope', 'regional')
        resource_identifier = result.get('resource_identifier', 'unknown')
        
        # Initialize account if not exists
        if account_id not in account_centric_report:
            account_centric_report[account_id] = {
                'account_name': account_name,
                'account_id': account_id,
                'regions': {},
                'global_services': {},
                'account_summary': {
                    'total_services': 0,
                    'enabled_services': 0,
                    'total_resources': 0,
                    'enablement_rate': 0.0
                }
            }
        
        # Determine where to place the service based on scope
        if scope == 'global':
            # Global services section
            if service not in account_centric_report[account_id]['global_services']:
                account_centric_report[account_id]['global_services'][service] = {
                    'service_name': service,
                    'enabled': enabled,
                    'resource_count': resource_count,
                    'resource_identifier_type': resource_identifier,
                    'resource_identifiers': [],
                    'scope': 'global'
                }
            
            # Add resource identifiers if service is enabled
            if enabled and resources:
                identifiers = [r.get('identifier', str(r)) for r in resources if r.get('identifier')]
                account_centric_report[account_id]['global_services'][service]['resource_identifiers'] = identifiers
        else:
            # Regional services section
            if region not in account_centric_report[account_id]['regions']:
                account_centric_report[account_id]['regions'][region] = {
                    'region_name': region,
                    'services': {},
                    'region_summary': {
                        'total_services': 0,
                        'enabled_services': 0,
                        'total_resources': 0,
                        'enablement_rate': 0.0
                    }
                }
            
            # Add service to region
            account_centric_report[account_id]['regions'][region]['services'][service] = {
                'service_name': service,
                'enabled': enabled,
                'resource_count': resource_count,
                'resource_identifier_type': resource_identifier,
                'resource_identifiers': [],
                'scope': 'regional'
            }
            
            # Add resource identifiers if service is enabled
            if enabled and resources:
                identifiers = [r.get('identifier', str(r)) for r in resources if r.get('identifier')]
                account_centric_report[account_id]['regions'][region]['services'][service]['resource_identifiers'] = identifiers
            
            # Update region summary
            account_centric_report[account_id]['regions'][region]['region_summary']['total_services'] += 1
            account_centric_report[account_id]['regions'][region]['region_summary']['total_resources'] += resource_count
            if enabled:
                account_centric_report[account_id]['regions'][region]['region_summary']['enabled_services'] += 1
        
        # Update account summary
        account_centric_report[account_id]['account_summary']['total_services'] += 1
        account_centric_report[account_id]['account_summary']['total_resources'] += resource_count
        if enabled:
            account_centric_report[account_id]['account_summary']['enabled_services'] += 1
    
    # Calculate enablement rates
    for account_id, account_data in account_centric_report.items():
        # Account level enablement rate
        total_services = account_data['account_summary']['total_services']
        enabled_services = account_data['account_summary']['enabled_services']
        account_data['account_summary']['enablement_rate'] = (enabled_services / total_services * 100) if total_services > 0 else 0.0
        
        # Region level enablement rates
        for region_name, region_data in account_data['regions'].items():
            total_services = region_data['region_summary']['total_services']
            enabled_services = region_data['region_summary']['enabled_services']
            region_data['region_summary']['enablement_rate'] = (enabled_services / total_services * 100) if total_services > 0 else 0.0
    
    # Calculate overall statistics
    total_service_instances = len(results)
    enabled_service_instances = sum(1 for r in results if r['enabled'])
    total_resource_count = sum(r.get('resource_count', 0) for r in results)
    
    # Build the comprehensive summary with new hierarchy
    enhanced_summary = {
        'scan_metadata': {
            'scan_session_id': scan_session_id,
            'scan_timestamp': scan_start_time.isoformat(),
            'scan_duration_minutes': scan_duration / 60,
            'total_checks_performed': len(results),
            'unique_services_checked': len(set(r['service'] for r in results)),
            'accounts_scanned': len(accounts),
            'regions_scanned': len(set(r['region'] for r in results if r['region'] != 'global')),
            'success_rate': (scan_stats['successful_calls'] / scan_stats['total_api_calls'] * 100) if scan_stats['total_api_calls'] > 0 else 0
        },
        
        'executive_summary': {
            'total_service_instances': total_service_instances,
            'enabled_service_instances': enabled_service_instances,
            'overall_enablement_rate': (enabled_service_instances / total_service_instances * 100) if total_service_instances > 0 else 0,
            'total_resources_discovered': total_resource_count,
            'unique_services': len(set(r['service'] for r in results)),
            'unique_regions': len(set(r['region'] for r in results if r['region'] != 'global')),
            'global_services_count': len([r for r in results if r.get('scope') == 'global']),
            'regional_services_count': len([r for r in results if r.get('scope') == 'regional'])
        },
        
        # NEW HIERARCHICAL STRUCTURE: Account → Region/Global → Services → Resources
        'account_service_inventory': account_centric_report,
        
        # Keep legacy breakdowns for compatibility but mark as deprecated
        'legacy_breakdowns': {
            'note': 'These breakdowns are maintained for compatibility. Use account_service_inventory for the hierarchical view.',
            
            'service_summary': {
                service: {
                    'scope': next((r.get('scope', 'regional') for r in results if r['service'] == service), 'regional'),
                    'total_instances': len([r for r in results if r['service'] == service]),
                    'enabled_instances': len([r for r in results if r['service'] == service and r['enabled']]),
                    'enablement_rate': (len([r for r in results if r['service'] == service and r['enabled']]) / 
                                      len([r for r in results if r['service'] == service]) * 100) 
                                      if len([r for r in results if r['service'] == service]) > 0 else 0,
                    'total_resources': sum(r.get('resource_count', 0) for r in results if r['service'] == service and r['enabled'])
                }
                for service in set(r['service'] for r in results)
            },
            
            'region_summary': {
                region: {
                    'total_services': len([r for r in results if r['region'] == region]),
                    'enabled_services': len([r for r in results if r['region'] == region and r['enabled']]),
                    'enablement_rate': (len([r for r in results if r['region'] == region and r['enabled']]) / 
                                      len([r for r in results if r['region'] == region]) * 100) 
                                      if len([r for r in results if r['region'] == region]) > 0 else 0,
                    'total_resources': sum(r.get('resource_count', 0) for r in results if r['region'] == region and r['enabled'])
                }
                for region in set(r['region'] for r in results)
            }
        },
        
        'error_analysis': {
            'total_errors': len(error_logger.errors),
            'error_categories': dict(error_logger.error_categories),
            'errors_by_service': dict(error_logger.service_errors),
            'errors_by_account': dict(error_logger.account_errors),
            'errors_by_region': dict(error_logger.region_errors)
        }
    }
    
    return enhanced_summary

# ---------- CSV Report Generator ----------
def generate_csv_reports(summary_data, session_reference, scan_output_dir):
    """Generate CSV format reports for the two main outputs"""
    import csv
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    
    # 1. Generate Account Service Inventory CSV
    account_service_csv = scan_output_dir / f"account_service_inventory_{timestamp}.csv"
    
    # Prepare data for Account → Region/Global → Services → Resource Identifiers CSV
    csv_rows = []
    
    for account_id, account_data in summary_data['account_service_inventory'].items():
        account_name = account_data['account_name']
        
        # Global services
        for service_name, service_data in account_data['global_services'].items():
            resource_identifiers = '; '.join(service_data.get('resource_identifiers', []))
            csv_rows.append({
                'Account_ID': account_id,
                'Account_Name': account_name,
                'Region_Type': 'Global',
                'Region_Name': 'global',
                'Service_Name': service_name,
                'Service_Enabled': service_data['enabled'],
                'Resource_Count': service_data['resource_count'],
                'Resource_Identifier_Type': service_data['resource_identifier_type'],
                'Resource_Identifiers': resource_identifiers,
                'Service_Scope': service_data['scope']
            })
        
        # Regional services
        for region_name, region_data in account_data['regions'].items():
            for service_name, service_data in region_data['services'].items():
                resource_identifiers = '; '.join(service_data.get('resource_identifiers', []))
                csv_rows.append({
                    'Account_ID': account_id,
                    'Account_Name': account_name,
                    'Region_Type': 'Regional',
                    'Region_Name': region_name,
                    'Service_Name': service_name,
                    'Service_Enabled': service_data.get('enabled', False),
                    'Resource_Count': service_data.get('resource_count', 0),
                    'Resource_Identifier_Type': service_data.get('resource_identifier_type', 'unknown'),
                    'Resource_Identifiers': resource_identifiers,
                    'Service_Scope': service_data.get('scope', 'regional')
                })
    
    # Write Account Service Inventory CSV
    with open(account_service_csv, 'w', newline='', encoding='utf-8') as f:
        fieldnames = [
            'Account_ID', 'Account_Name', 'Region_Type', 'Region_Name', 
            'Service_Name', 'Service_Enabled', 'Resource_Count', 
            'Resource_Identifier_Type', 'Resource_Identifiers', 'Service_Scope'
        ]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(csv_rows)
    
    # 2. Generate Session Reference CSV
    session_reference_csv = scan_output_dir / f"scan_session_reference_{timestamp}.csv"
    
    # Flatten session reference data for CSV
    session_csv_data = {
        'Scan_Session_ID': session_reference['scan_session_id'],
        'Scan_Start_Timestamp': session_reference['scan_timestamp'],
        'Scan_End_Timestamp': session_reference['scan_end_timestamp'],
        'Scan_Duration_Seconds': session_reference['scan_duration_seconds'],
        'Scan_Duration_Minutes': session_reference['scan_duration_minutes'],
        'Total_Accounts': session_reference['total_accounts'],
        'Total_Regions': session_reference['total_regions'],
        'Total_Services': session_reference['total_services'],
        'Total_Checks_Performed': session_reference['total_checks_performed'],
        'Total_API_Calls': session_reference['total_api_calls'],
        'Success_Rate_Percent': session_reference['success_rate'],
        'Enabled_Service_Instances': session_reference['quick_stats']['enabled_service_instances'],
        'Total_Service_Instances': session_reference['quick_stats']['total_service_instances'],
        'Enablement_Rate_Percent': session_reference['quick_stats']['enablement_rate'],
        'Unique_Enabled_Services': session_reference['quick_stats']['unique_enabled_services'],
        'Total_Errors': session_reference['quick_stats']['total_errors']
    }
    
    # Write Session Reference CSV
    with open(session_reference_csv, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['Metric', 'Value'])  # Header
        for key, value in session_csv_data.items():
            writer.writerow([key.replace('_', ' '), value])
    
    print(f"✅ Generated CSV reports:")
    print(f"   📋 Account Service Inventory: {account_service_csv.name}")
    print(f"   📊 Session Reference: {session_reference_csv.name}")
    
    return {
        'account_service_inventory': str(account_service_csv),
        'session_reference': str(session_reference_csv)
    }

def generate_service_enablement_matrix(results, accounts):
    """Generate service enablement matrix for detailed analysis"""
    matrix = []
    
    # Account → Service → Region breakdown
    account_service_region = defaultdict(lambda: defaultdict(lambda: defaultdict(dict)))
    
    for result in results:
        account_id = result['account_id']
        service = result['service']
        region = result['region']
        enabled = result['enabled']
        resource_count = result.get('resource_count', 0)
        resources = result.get('resources', [])
        scope = result.get('scope', 'regional')
        
        # Skip if no resources and not globally enabled
        if not resources and not enabled:
            continue
        
        account_service_region[account_id][service][region] = {
            'enabled': enabled,
            'resource_count': resource_count,
            'resources': resources,
            'scope': scope
        }
    
    # Generate matrix rows
    for account_id, services in account_service_region.items():
        for service, regions in services.items():
            for region, data in regions.items():
                matrix.append({
                    'Account_ID': account_id,
                    'Service_Name': service,
                    'Region_Name': region,
                    'Enabled': data['enabled'],
                    'Resource_Count': data['resource_count'],
                    'Scope': data['scope'],
                    'Resources': '; '.join(r.get('identifier', str(r)) for r in data['resources'])
                })
    
    return matrix

# ---------- Enterprise Service Enablement Checker ----------
def create_enterprise_service_enablement_checker():
    """Create enterprise service enablement checker with multi-account support"""
    
    # Load service mapping
    def load_service_mapping():
        mapping_file = SCRIPT_DIR / "service_enablement_mapping.json"
        try:
            with open(mapping_file, 'r') as f:
                mapping = json.load(f)
                print(f"✅ Successfully loaded service mapping from {mapping_file.name}")
                return mapping
        except FileNotFoundError:
            print(f"❌ Service mapping file not found: {mapping_file}")
            print(f"💡 Please ensure service_enablement_mapping.json exists in the inventory directory")
            raise FileNotFoundError(f"Required service mapping file not found: {mapping_file}")
        except json.JSONDecodeError as e:
            print(f"❌ Invalid JSON in service mapping file: {e}")
            print(f"💡 Please check the JSON syntax in {mapping_file}")
            raise
        except Exception as e:
            print(f"❌ Error loading service mapping: {e}")
            raise
    
    service_mapping = load_service_mapping()
    print(f"📋 Loaded mapping for {len(service_mapping)} services")
    
    # Validate mapping structure
    valid_services = 0
    for service_name, config in service_mapping.items():
        if all(key in config for key in ['client_type', 'check_function', 'scope']):
            valid_services += 1
        else:
            print(f"⚠️  Service '{service_name}' missing required fields (client_type, check_function, scope)")
    
    print(f"📋 Validated {valid_services}/{len(service_mapping)} services have complete configuration")
    
    def get_enhanced_client(session, client_type, region):
        """Get enhanced AWS client with enterprise configuration"""
        # Use proper scope-based region selection
        if client_type in GLOBAL_SERVICES:
            region = GLOBAL_SERVICES[client_type]
        
        config = Config(
            retries={'max_attempts': MAX_RETRIES, 'mode': 'adaptive'},
            read_timeout=TIMEOUT_SECONDS,
            connect_timeout=15,
            max_pool_connections=100,
            region_name=region
        )
        
        return session.client(client_type, config=config)
    
    def extract_resource_info(response, resource_identifier, count_field, service_name):
        """Extract resource information from AWS API response using mapping configuration"""
        try:
            if not response or not count_field:
                return 0, []
            
            # Handle different response structures based on count_field format
            resources = []
            
            # Parse the count_field to navigate the response structure
            if count_field.endswith('[*]'):
                # Handle array fields like "TableNames[*]", "QueueUrls[*]", etc.
                field_name = count_field.replace('[*]', '')
                if field_name in response and isinstance(response[field_name], list):
                    # Direct array of strings (like TableNames, QueueUrls)
                    for item in response[field_name]:
                        if isinstance(item, str):
                            resources.append({
                                'identifier': item,
                                'service': service_name,
                                'type': resource_identifier
                            })
                        elif isinstance(item, dict) and resource_identifier in item:
                            # Object with identifier field
                            resources.append({
                                'identifier': item[resource_identifier],
                                'service': service_name,
                                'type': resource_identifier
                            })
                    
            elif '.' in count_field and '[*]' in count_field:
                # Handle nested structures like "Buckets[*].Name", "Users[*].UserName"
                parts = count_field.split('.')
                current_data = response
                
                # Navigate to the array
                for part in parts[:-1]:
                    if '[*]' in part:
                        field_name = part.replace('[*]', '')
                        if field_name in current_data and isinstance(current_data[field_name], list):
                            current_data = current_data[field_name]
                            break
                    else:
                        if part in current_data:
                            current_data = current_data[part]
                        else:
                            return 0, []
                
                # Extract the final field from each item in the array
                final_field = parts[-1]
                if isinstance(current_data, list):
                    for item in current_data:
                        if isinstance(item, dict):
                            # Extract the identifier
                            identifier_value = None
                            if final_field in item:
                                identifier_value = item[final_field]
                            elif resource_identifier in item:
                                identifier_value = item[resource_identifier]
                            
                            if identifier_value:
                                resource_info = {
                                    'identifier': identifier_value,
                                    'service': service_name,
                                    'type': resource_identifier
                                }
                                
                                # Add additional useful fields if available
                                common_fields = ['Name', 'State', 'Status', 'CreatedTime', 'LaunchTime']
                                for field in common_fields:
                                    if field in item:
                                        resource_info[field.lower()] = item[field]
                                
                                resources.append(resource_info)
                        elif isinstance(item, str):
                            # Simple string value
                            resources.append({
                                'identifier': item,
                                'service': service_name,
                                'type': resource_identifier
                            })
            
            elif count_field in response:
                # Direct field access like "DetectorIds", "StreamNames"
                data = response[count_field]
                if isinstance(data, list):
                    for item in data:
                        if isinstance(item, str):
                            resources.append({
                                'identifier': item,
                                'service': service_name,
                                'type': resource_identifier
                            })
                        elif isinstance(item, dict) and resource_identifier in item:
                            resources.append({
                                'identifier': item[resource_identifier],
                                'service': service_name,
                                'type': resource_identifier
                            })
            
            # Handle special cases for services with complex nested structures
            if service_name == 'ec2' and 'Reservations' in response:
                # EC2 instances are nested in Reservations
                for reservation in response['Reservations']:
                    if 'Instances' in reservation:
                        for instance in reservation['Instances']:
                            if 'InstanceId' in instance:
                                resource_info = {
                                    'identifier': instance['InstanceId'],
                                    'service': service_name,
                                    'type': 'InstanceId'
                                }
                                if 'State' in instance:
                                    resource_info['state'] = instance['State'].get('Name', 'unknown')
                                if 'InstanceType' in instance:
                                    resource_info['instance_type'] = instance['InstanceType']
                                resources.append(resource_info)
            
            elif service_name == 'cloudfront' and 'DistributionList' in response:
                # CloudFront distributions
                dist_list = response['DistributionList']
                if 'Items' in dist_list:
                    for item in dist_list['Items']:
                        if 'Id' in item:
                            resource_info = {
                                'identifier': item['Id'],
                                'service': service_name,
                                'type': 'Id'
                            }
                            if 'DomainName' in item:
                                resource_info['domain_name'] = item['DomainName']
                            if 'Status' in item:
                                resource_info['status'] = item['Status']
                            resources.append(resource_info)
            
            elif service_name == 'wafv2':
                # WAFv2 needs Scope parameter
                if 'WebACLs' in response:
                    for acl in response['WebACLs']:
                        if 'Id' in acl:
                            resources.append({
                                'identifier': acl['Id'],
                                'service': service_name,
                                'type': 'Id',
                                'name': acl.get('Name', ''),
                                'scope': acl.get('Scope', 'REGIONAL')
                            })
            
            return len(resources), resources
                
        except Exception as e:
            print(f"⚠️  Could not parse resource info for {service_name}: {str(e)}")
            
            # Fallback: try to determine if service is enabled by checking for non-empty response
            if isinstance(response, dict):
                # Look for common list fields that might indicate resources
                for key, value in response.items():
                    if isinstance(value, list) and len(value) > 0:
                        # Service appears to be enabled with some resources
                        fallback_resources = []
                        for item in value[:5]:  # Limit to first 5 for safety
                            if isinstance(item, dict):
                                # Try to find an identifier field
                                identifier = None
                                for id_field in ['Id', 'Name', 'Arn', 'identifier']:
                                    if id_field in item:
                                        identifier = item[id_field]
                                        break
                                if identifier:
                                    fallback_resources.append({
                                        'identifier': str(identifier),
                                        'service': service_name,
                                        'type': id_field,
                                        'source': 'fallback_detection'
                                    })
                            elif isinstance(item, str):
                                fallback_resources.append({
                                    'identifier': item,
                                    'service': service_name,
                                    'type': 'unknown',
                                    'source': 'fallback_detection'
                                })
                        
                        if fallback_resources:
                            return len(fallback_resources), fallback_resources
            
            return 0, []
    
    def check_service_in_account_region(account_info, service_name, region, error_logger):
        """Enhanced service checking with comprehensive error handling using new mapping format"""
        account_id = account_info['account_id']
        session = account_info['session']
        
        try:
            # Get service configuration from mapping
            service_config = service_mapping.get(service_name)
            
            if not service_config:
                return {
                    'service': service_name,
                    'region': region,
                    'account_id': account_id,
                    'enabled': False,
                    'error': 'Service not found in mapping',
                    'functions_checked': 0,
                    'functions_successful': 0,
                    'resource_count': 0,
                    'resources': []
                }
            
            # Extract configuration
            client_type = service_config.get('client_type', service_name)
            check_function = service_config.get('check_function')
            scope = service_config.get('scope', 'regional')
            resource_identifier = service_config.get('resource_identifier')
            count_field = service_config.get('count_field')
            
            # Skip global services in regional scans and vice versa
            if scope == 'global' and region != 'global':
                return None  # Skip this combination
            elif scope == 'regional' and region == 'global':
                return None  # Skip this combination
            
            # Create the appropriate client
            actual_region = region if scope == 'regional' else 'us-east-1'
            client = get_enhanced_client(session, client_type, actual_region)
            
            if not check_function:
                return {
                    'service': service_name,
                    'region': region,
                    'account_id': account_id,
                    'enabled': False,
                    'error': 'No check function defined for service',
                    'functions_checked': 0,
                    'functions_successful': 0,
                    'resource_count': 0,
                    'resources': []
                }
            
            successful_functions = []
            failed_functions = []
            resource_count = 0
            resources = []
            
            try:
                if hasattr(client, check_function):
                    func = getattr(client, check_function)
                    
                    # Execute function with special parameters for certain services
                    response = None
                    if service_name == 'wafv2':
                        # WAFv2 requires Scope parameter
                        response = func(Scope='REGIONAL')
                    elif service_name == 'cloudformation':
                        # CloudFormation - only get active stacks
                        response = func(StackStatusFilter=['CREATE_COMPLETE', 'UPDATE_COMPLETE', 'DELETE_FAILED'])
                    elif service_name == 'emr':
                        # EMR - only get active clusters
                        response = func(ClusterStates=['WAITING', 'RUNNING'])
                    elif service_name == 'cloudwatch':
                        # CloudWatch - limit metrics to reduce response size
                        response = func(MaxRecords=100)
                    else:
                        response = func()
                        
                    if response:
                        successful_functions.append(check_function)
                        
                        # Extract resource information using the mapping configuration
                        resource_count, resources = extract_resource_info(
                            response, resource_identifier, count_field, service_name
                        )
                    
                    # Update stats
                    with lock:
                        scan_stats['successful_calls'] += 1
                        scan_stats['total_api_calls'] += 1
                        
                else:
                    error_logger.log_error(
                        account_id, region, service_name, check_function,
                        'function_not_found', f"Function {check_function} not found on {client_type} client"
                    )
                    failed_functions.append(check_function)
                    
                    with lock:
                        scan_stats['failed_calls'] += 1
                        scan_stats['total_api_calls'] += 1
            
            except Exception as e:
                error_type = error_logger.categorize_error(e)
                error_logger.log_error(account_id, region, service_name, check_function, error_type, str(e))
                failed_functions.append(check_function)
                
                with lock:
                    scan_stats['failed_calls'] += 1
                    scan_stats['total_api_calls'] += 1
            
            # Determine service enablement (since we only have one function, it's binary)
            is_enabled = len(successful_functions) > 0
            
            return {
                'service': service_name,
                'region': region,
                'account_id': account_id,
                'account_name': account_info['name'],
                'enabled': is_enabled,
                'functions_checked': 1,
                'functions_successful': len(successful_functions),
                'functions_failed': len(failed_functions),
                'success_rate': 1.0 if is_enabled else 0.0,
                'successful_functions': successful_functions,
                'failed_functions': failed_functions,
                'client_type': client_type,
                'check_function': check_function,
                'scope': scope,
                'resource_count': resource_count,
                'resources': resources,
                'resource_identifier': resource_identifier,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
            
        except Exception as e:
            error_type = error_logger.categorize_error(e)
            error_logger.log_error(account_id, region, service_name, 'service_client', error_type, str(e))
            
            with lock:
                scan_stats['failed_calls'] += 1
                scan_stats['total_api_calls'] += 1
            
            return {
                'service': service_name,
                'region': region,
                'account_id': account_id,
                'account_name': account_info['name'],
                'enabled': False,
                'error': str(e),
                'error_type': error_type,
                'functions_checked': 0,
                'functions_successful': 0,
                'resource_count': 0,
                'resources': [],
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
    
    def run_enterprise_multi_account_scan(account_manager, max_workers=MAX_WORKERS):
        """Run enterprise-scale multi-account service enablement scan"""
        print(f"🚀 Starting Enterprise Multi-Account Service Enablement Scan...")
        
        # Generate unique scan session ID
        scan_session_id = f"enterprise_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"
        scan_start_time = datetime.now(timezone.utc)
        
        print(f"   🆔 Scan Session: {scan_session_id}")
        print(f"   🏢 Accounts: {len(account_manager.accounts)}")
        print(f"   📦 Services: {len(service_mapping)}")
        print(f"   🧵 Max Workers: {max_workers}")
        
        # Calculate total scope
        total_accounts, total_regions = account_manager.get_total_scan_scope()
        total_tasks = total_accounts * len(service_mapping) * (total_regions // total_accounts if total_accounts > 0 else 0)
        
        print(f"   📊 Total Scope: {total_tasks} service checks across {total_regions} regions")
        
        # Create output directory structure
        scan_output_dir = SCRIPT_DIR / "service_enablement_results" / f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        scan_output_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize error logger
        error_logger = EnterpriseErrorLogger(scan_session_id)
        
        # Results collection
        all_results = []
        # Fix: Initialize summary dictionaries properly
        region_summary = defaultdict(lambda: {'total': 0, 'enabled': 0})
        account_summary = defaultdict(lambda: {'total': 0, 'enabled': 0})
        service_summary = defaultdict(lambda: {'total': 0, 'enabled': 0})
        
        # Phase 1: Multi-threaded service checking
        print(f"\n🔍 Phase 1: Multi-Account Service Discovery...")
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = []
            
            # Submit all tasks
            for account_info in account_manager.accounts:
                account_id = account_info['account_id']
                
                for service_name, service_config in service_mapping.items():
                    scope = service_config.get('scope', 'regional')
                    
                    if scope == 'global':
                        # Submit global service check once per account
                        futures.append(executor.submit(
                            check_service_in_account_region,
                            account_info, service_name, "global", error_logger
                        ))
                    else:
                        # Submit regional service check for each enabled region
                        for region in account_info['enabled_regions']:
                            futures.append(executor.submit(
                                check_service_in_account_region,
                                account_info, service_name, region, error_logger
                            ))
            
            # Process results as they complete
            completed = 0
            for future in as_completed(futures):
                try:
                    result = future.result()
                    
                    # Skip None results (happens when we skip certain service/region combinations)
                    if result is None:
                        completed += 1
                        continue
                        
                    all_results.append(result)
                    
                    # Update summaries
                    account_id = result['account_id']
                    region = result['region']
                    service = result['service']
                    
                    region_summary[region]['total'] += 1
                    account_summary[account_id]['total'] += 1
                    service_summary[service]['total'] += 1
                    
                    if result['enabled']:
                        region_summary[region]['enabled'] += 1
                        account_summary[account_id]['enabled'] += 1
                        service_summary[service]['enabled'] += 1
                    
                    completed += 1
                    
                    # Progress update
                    if completed % 50 == 0 or completed == len(futures):
                        percentage = (completed / len(futures)) * 100
                        print(f"   Progress: {completed}/{len(futures)} ({percentage:.1f}%) - {result['service']} in {result['region']}")
                
                except Exception as e:
                    print(f"   ⚠️  Task failed: {str(e)}")
                    completed += 1
        
        scan_end_time = datetime.now(timezone.utc)
        scan_duration = (scan_end_time - scan_start_time).total_seconds()
        
        # Phase 2: Generate comprehensive reports
        print(f"\n📊 Phase 2: Generating Enterprise Reports...")
        
        # Save detailed results
        detailed_results_file = scan_output_dir / f"detailed_enablement_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(detailed_results_file, 'w') as f:
            json.dump({
                'scan_metadata': {
                    'scan_session_id': scan_session_id,
                    'scan_start_time': scan_start_time.isoformat(),
                    'scan_end_time': scan_end_time.isoformat(),
                    'scan_duration_seconds': scan_duration,
                    'total_accounts': len(account_manager.accounts),
                    'total_services_checked': len(service_mapping),
                    'total_api_calls': scan_stats['total_api_calls'],
                    'successful_calls': scan_stats['successful_calls'],
                    'failed_calls': scan_stats['failed_calls']
                },
                'accounts': [
                    {
                        'name': acc['name'],
                        'account_id': acc['account_id'],
                        'user_arn': acc['user_arn'],
                        'auth_method': acc['auth_method'],
                        'enabled_regions': len(acc['enabled_regions'])
                    } for acc in account_manager.accounts
                ],
                'results': all_results
            }, f, indent=2, default=str)
        
        # Generate service enablement matrix
        matrix_data = generate_service_enablement_matrix(all_results, account_manager.accounts)
        matrix_file = scan_output_dir / f"service_enablement_matrix_#{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(matrix_file, 'w') as f:
            json.dump(matrix_data, f, indent=2, default=str)
        
        # Generate enhanced summary report with regional breakdown and resource details
        summary_data = generate_enhanced_summary_report(
            all_results, account_manager.accounts, scan_session_id, 
            scan_start_time, scan_duration, scan_stats, error_logger
        )
        
        summary_file = scan_output_dir / f"service_enablement_summary_#{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(summary_file, 'w') as f:
            json.dump(summary_data, f, indent=2, default=str)
        
        # Create session reference
        session_reference = {
            "scan_session_id": scan_session_id,
            "scan_timestamp": scan_start_time.isoformat(),
            "scan_end_timestamp": scan_end_time.isoformat(),
            "scan_duration_seconds": scan_duration,
            "scan_duration_minutes": scan_duration / 60,
            "total_accounts": len(account_manager.accounts),
            "total_regions": len(set(r['region'] for r in all_results)),
            "total_services": len(service_mapping),
            "total_checks_performed": len(all_results),
            "total_api_calls": scan_stats['total_api_calls'],
            "success_rate": (scan_stats['successful_calls'] / scan_stats['total_api_calls'] * 100) if scan_stats['total_api_calls'] > 0 else 0,
            "files_generated": {
                "detailed_results": str(detailed_results_file.name),
                "service_matrix": str(matrix_file.name),
                "summary_report": str(summary_file.name)
            },
            "quick_stats": {
                "enabled_service_instances": sum(1 for r in all_results if r['enabled']),
                "total_service_instances": len(all_results),
                "enablement_rate": (sum(1 for r in all_results if r['enabled']) / len(all_results) * 100) if all_results else 0,
                "unique_enabled_services": len(set(r['service'] for r in all_results if r['enabled'])),
                "total_errors": len(error_logger.errors)
            }
        }
        
        # Generate CSV reports with proper session reference
        csv_files = generate_csv_reports(summary_data, session_reference, scan_output_dir)
        
        # Add CSV files to session reference
        session_reference["csv_files"] = csv_files
        
        # Save comprehensive error analysis
        if error_logger.errors:
            save_comprehensive_error_analysis(error_logger.errors, scan_output_dir, {
                'scan_session_id': scan_session_id,
                'scan_start_time': scan_start_time.isoformat(),
                'scan_end_time': scan_end_time.isoformat(),
                'scan_duration_seconds': scan_duration
            })
        
        session_file = scan_output_dir / f"scan_session_reference_#{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(session_file, 'w') as f:
            json.dump(session_reference, f, indent=2, default=str)
        
        # Create/update latest scan symlink
        latest_link = scan_output_dir.parent / "latest_scan"
        if latest_link.exists() or latest_link.is_symlink():
            latest_link.unlink()
        latest_link.symlink_to(scan_output_dir.name)
        
        # Print comprehensive summary
        print_enterprise_scan_summary(scan_session_id, scan_duration, all_results, 
                                    account_manager.accounts, error_logger, scan_output_dir)
        
        # Phase 3: Run integrated error analysis
        if ERROR_ANALYZER_AVAILABLE and error_logger.errors:
            print(f"\n🔍 Phase 3: Integrated Error Analysis...")
            try:
                analysis_results = run_post_scan_analysis(scan_output_dir, session_reference)
                if analysis_results:
                    print(f"✅ Post-scan error analysis completed")
                    print(f"📊 Analysis results integrated into scan directory")
                else:
                    print(f"ℹ️  No errors to analyze - this is good news!")
            except Exception as e:
                print(f"⚠️  Post-scan analysis failed: {str(e)}")
                print(f"📝 You can run the error analyzer manually later")
        elif not ERROR_ANALYZER_AVAILABLE:
            print(f"\n💡 To enable post-scan error analysis:")
            print(f"   1. Ensure pandas is installed: pip install pandas")
            print(f"   2. Run error_analyzer.py after the scan completes")
        elif not error_logger.errors:
            print(f"\n🎉 No errors detected during scan - excellent performance!")
        
        return scan_output_dir, session_reference
    
    return check_service_in_account_region, run_enterprise_multi_account_scan

# ---------- Helper Functions ----------

def save_comprehensive_error_analysis(errors_data, scan_dir, scan_metadata):
    """Save comprehensive error analysis with timestamp management"""
    if not errors_data:
        return None
    
    # Create error logs structure
    error_logs_dir = scan_dir / "error_logs"
    error_logs_dir.mkdir(exist_ok=True)
    
    # Create subdirectories for organized error analysis
    subdirs = ["detailed_analysis", "temporal_analysis", "service_analysis", "regional_analysis", "recommendations"]
    for subdir in subdirs:
        (error_logs_dir / subdir).mkdir(exist_ok=True)
    
    # Generate timestamp for this analysis
    analysis_timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    session_id = f"error_analysis_{analysis_timestamp}_{uuid.uuid4().hex[:8]}"
    
    # Save main error summary
    summary_file = error_logs_dir / f"error_summary_{analysis_timestamp}.json"
    with open(summary_file, 'w') as f:
        json.dump({
            "scan_metadata": scan_metadata,
            "analysis_session_id": session_id,
            "analysis_timestamp": datetime.now(timezone.utc).isoformat(),
            "total_errors": len(errors_data),
            "errors": errors_data
        }, f, indent=2, default=str)
    
    # Save CSV format for easy analysis
    csv_file = error_logs_dir / f"errors_summary_{analysis_timestamp}.csv"
    with open(csv_file, 'w', newline='', encoding='utf-8') as f:
        if errors_data:
            fieldnames = errors_data[0].keys()
            import csv
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(errors_data)
    
    # Create session reference
    session_reference = {
        "analysis_session_id": session_id,
        "analysis_timestamp": datetime.now(timezone.utc).isoformat(),
        "scan_session_id": scan_metadata.get("scan_session_id"),
        "total_errors_analyzed": len(errors_data),
        "files_generated": {
            "summary": str(summary_file.name),
            "csv_export": str(csv_file.name)
        }
    }
    
    session_file = error_logs_dir / f"analysis_session_reference_{analysis_timestamp}.json"
    with open(session_file, 'w') as f:
        json.dump(session_reference, f, indent=2, default=str)
    
    return error_logs_dir, session_reference

def print_enterprise_scan_summary(scan_session_id, scan_duration, results, accounts, error_logger, output_dir):
    """Print comprehensive enterprise scan summary"""
    print(f"\n{'='*100}")
    print(f"🏢 ENTERPRISE MULTI-ACCOUNT SERVICE ENABLEMENT SCAN RESULTS")
    print(f"{'='*100}")
    
    # Scan metadata
    print(f"🆔 Scan Session ID: {scan_session_id}")
    print(f"⏱️  Scan Duration: {scan_duration:.2f} seconds ({scan_duration/60:.1f} minutes)")
    print(f"🏢 Accounts Scanned: {len(accounts)}")
    
    # Account details
    for account in accounts:
        print(f"   📋 {account['name']} ({account['account_id']}) - {len(account['enabled_regions'])} regions via {account['auth_method']}")
    
    # Service statistics
    total_checks = len(results)
    enabled_services = sum(1 for r in results if r['enabled'])
    enablement_rate = (enabled_services / total_checks * 100) if total_checks > 0 else 0
    
    print(f"\n📊 SERVICE ENABLEMENT STATISTICS:")
    print(f"   🔍 Total Service Checks: {total_checks:,}")
    print(f"   ✅ Services Enabled: {enabled_services:,}")
    print(f"   📈 Overall Enablement Rate: {enablement_rate:.1f}%")
    print(f"   🌍 Unique Regions: {len(set(r['region'] for r in results))}")
    print(f"   📦 Unique Services: {len(set(r['service'] for r in results))}")
    
    # API call statistics
    print(f"\n📞 API CALL STATISTICS:")
    print(f"   📞 Total API Calls: {scan_stats['total_api_calls']:,}")
    print(f"   ✅ Successful Calls: {scan_stats['successful_calls']:,}")
    print(f"   ❌ Failed Calls: {scan_stats['failed_calls']:,}")
    print(f"   📈 Success Rate: {(scan_stats['successful_calls']/scan_stats['total_api_calls']*100):.1f}%" if scan_stats['total_api_calls'] > 0 else "0%")
    print(f"   ⚡ Calls per Second: {scan_stats['total_api_calls']/scan_duration:.1f}")
    
    # Error analysis
    print(f"\n🔍 ERROR ANALYSIS:")
    print(f"   📊 Total Errors: {len(error_logger.errors):,}")
    
    if error_logger.error_categories:
        print(f"   🏷️  Error Categories:")
        for error_type, count in error_logger.error_categories.most_common(10):
            percentage = (count / len(error_logger.errors) * 100) if error_logger.errors else 0
            print(f"      • {error_type}: {count:,} ({percentage:.1f}%)")
    
    # Top problematic services
    if error_logger.service_errors:
        print(f"   ⚠️  Most Problematic Services:")
        service_totals = {service: sum(errors.values()) for service, errors in error_logger.service_errors.items()}
        for i, (service, total) in enumerate(sorted(service_totals.items(), key=lambda x: x[1], reverse=True)[:5], 1):
            print(f"      {i}. {service}: {total:,} errors")
    
    # Regional analysis
    if error_logger.region_errors:
        print(f"   🌍 Most Problematic Regions:")
        region_totals = {region: sum(errors.values()) for region, errors in error_logger.region_errors.items()}
        for i, (region, total) in enumerate(sorted(region_totals.items(), key=lambda x: x[1], reverse=True)[:5], 1):
            print(f"      {i}. {region}: {total:,} errors")
    
    # Output files
    print(f"\n📁 OUTPUT FILES:")
    print(f"   📂 Main Directory: {output_dir}")
    print(f"   📊 Detailed Results: detailed_enablement_results_*.json")
    print(f"   🔢 Service Matrix: service_enablement_matrix_*.json") 
    print(f"   📋 Summary Report: service_enablement_summary_*.json")
    print(f"   📄 CSV Reports: account_service_inventory_*.csv, scan_session_reference_*.csv")
    if error_logger.errors:
        print(f"   🔍 Error Logs: error_logs/")
        print(f"   📄 Error CSV: error_logs/errors_summary_*.csv")
    
    print(f"{'='*100}")

def setup_enterprise_multi_account_access():
    """Setup enterprise multi-account access with advanced options"""
    account_manager = EnterpriseAccountManager()
    
    print("🏢 Enterprise Multi-Account AWS Setup")
    print("Choose your authentication method:")
    print("1. Default credentials (single account)")
    print("2. Multiple access key pairs")
    print("3. AWS CLI profiles")
    print("4. Cross-account IAM roles")
    print("5. Mixed authentication (combination)")
    
    choice = input("Enter your choice (1-5): ").strip()
    
    if choice == "1":
        # Default credentials
        success = account_manager.add_account("primary")
        if not success:
            print("❌ Failed to setup default credentials")
            return None
    
    elif choice == "2":
        # Multiple access keys
        account_count = int(input("How many accounts? "))
        for i in range(account_count):
            print(f"\n--- Account {i+1} ---")
            name = input(f"Account name: ").strip()
            access_key = input(f"AWS Access Key ID: ").strip()
            secret_key = input(f"AWS Secret Access Key: ").strip()
            session_token = input(f"Session Token (optional, press Enter to skip): ").strip()
            session_token = session_token if session_token else None
            
            account_manager.add_account(name, access_key, secret_key, session_token)
    
    elif choice == "3":
        # AWS CLI profiles
        import subprocess
        try:
            result = subprocess.run(['aws', 'configure', 'list-profiles'], 
                                  capture_output=True, text=True, check=True)
            profiles = [p.strip() for p in result.stdout.strip().split('\n') if p.strip()]
            
            if not profiles:
                print("❌ No AWS CLI profiles found")
                return None
            
            print(f"📋 Available profiles: {', '.join(profiles)}")
            
            selected_profiles = input("Enter profile names (comma-separated): ").strip().split(',')
            for profile in selected_profiles:
                profile = profile.strip()
                if profile in profiles:
                    account_manager.add_account(profile, profile=profile)
                else:
                    print(f"⚠️  Profile '{profile}' not found, skipping...")
        
        except subprocess.CalledProcessError:
            print("❌ AWS CLI not found or not configured")
            return None
        except FileNotFoundError:
            print("❌ AWS CLI not installed")
            return None
    
    elif choice == "4":
        # Cross-account IAM roles
        role_count = int(input("How many cross-account roles? "))
        for i in range(role_count):
            print(f"\n--- Role {i+1} ---")
            name = input(f"Account name: ").strip()
            role_arn = input(f"Role ARN: ").strip()
            external_id = input(f"External ID (optional, press Enter to skip): ").strip()
            external_id = external_id if external_id else None
            
            # Optional base credentials
            use_base_creds = input("Use specific base credentials? (y/n): ").strip().lower() == 'y'
            if use_base_creds:
                access_key = input(f"Base AWS Access Key ID: ").strip()
                secret_key = input(f"Base AWS Secret Access Key: ").strip()
                account_manager.add_account(name, access_key, secret_key, 
                                          role_arn=role_arn, external_id=external_id)
            else:
                account_manager.add_account(name, role_arn=role_arn, external_id=external_id)
    
    elif choice == "5":
        # Mixed authentication
        print("🔧 Mixed Authentication Setup")
        while True:
            print("\nAdd account via:")
            print("1. Access keys")
            print("2. CLI profile") 
            print("3. IAM role")
            print("4. Done adding accounts")
            
            sub_choice = input("Choice: ").strip()
            
            if sub_choice == "4":
                break
            elif sub_choice == "1":
                name = input("Account name: ").strip()
                access_key = input("AWS Access Key ID: ").strip()
                secret_key = input("AWS Secret Access Key: ").strip()
                account_manager.add_account(name, access_key, secret_key)
            elif sub_choice == "2":
                name = input("Account name: ").strip()
                profile = input("AWS CLI profile: ").strip()
                account_manager.add_account(name, profile=profile)
            elif sub_choice == "3":
                name = input("Account name: ").strip()
                role_arn = input("Role ARN: ").strip()
                external_id = input("External ID (optional): ").strip()
                external_id = external_id if external_id else None
                account_manager.add_account(name, role_arn=role_arn, external_id=external_id)
    
    else:
        print("❌ Invalid choice")
        return None
    
    if len(account_manager.accounts) == 0:
        print("❌ No accounts configured successfully")
        return None
    
    print(f"\n✅ Successfully configured {len(account_manager.accounts)} accounts")
    return account_manager

def main():
    """Main entry point for enterprise multi-account service enablement scanning"""
    print("🚀 Enterprise AWS Multi-Account Service Enablement Checker")
    print("📋 Advanced service discovery with comprehensive error analysis")
    
    # Load service mapping first to initialize global services
    try:
        load_service_mapping()
    except Exception as e:
        print(f"❌ Failed to load service mapping: {e}")
        return
    
    # Setup multi-account access
    account_manager = setup_enterprise_multi_account_access()
    if not account_manager:
        print("❌ Failed to setup multi-account access")
        return
    
    # Configuration options
    print(f"\n⚙️  SCAN CONFIGURATION:")
    print(f"   🧵 Default max workers: {MAX_WORKERS}")
    print(f"   ⏱️  Timeout per API call: {TIMEOUT_SECONDS} seconds")
    print(f"   🔄 Max retries: {MAX_RETRIES}")
    
    # Allow user to customize
    customize = input("Customize scan parameters? (y/n): ").strip().lower() == 'y'
    max_workers = MAX_WORKERS
    
    if customize:
        try:
            max_workers = int(input(f"Max concurrent workers [{MAX_WORKERS}]: ").strip() or MAX_WORKERS)
            max_workers = max(1, min(max_workers, 50))  # Reasonable bounds
        except ValueError:
            max_workers = MAX_WORKERS
        
        print(f"✅ Using {max_workers} workers")
    
    # Create and run enterprise scanner
    check_service_func, run_scan_func = create_enterprise_service_enablement_checker()
    
    print(f"\n🎯 Starting enterprise scan...")
    scan_output_dir, session_reference = run_scan_func(account_manager, max_workers)
    
    # Final summary
    print(f"\n🎉 Enterprise scan completed successfully!")
    print(f"📁 Results saved to: {scan_output_dir}")
    print(f"🔗 Latest scan link: {scan_output_dir.parent / 'latest_scan'}")
    print(f"🆔 Session ID: {session_reference['scan_session_id']}")

if __name__ == "__main__":
    main()
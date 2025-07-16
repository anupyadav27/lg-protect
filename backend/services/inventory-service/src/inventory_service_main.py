#!/usr/bin/env python3
"""
Inventory Service for LG-Protect Platform
Event-driven AWS resource discovery and inventory management with integrated discovery engines
Enhanced for Enterprise Multi-Account Support
"""

import os
import sys
import json
import asyncio
import logging
import uuid
import threading
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
from pathlib import Path
from collections import defaultdict, Counter
from concurrent.futures import ThreadPoolExecutor, as_completed

# Add the app directory to Python path for imports
sys.path.append('/app')

import boto3
from botocore.exceptions import ClientError, NoCredentialsError, EndpointConnectionError
import structlog

# Import shared modules with correct paths using importlib to handle hyphens
import importlib.util

# Import from event-bus directory (Python doesn't like hyphens in imports)
event_bus_spec = importlib.util.spec_from_file_location("event_bus", "/app/shared/event-bus/event_bus.py")
event_bus_module = importlib.util.module_from_spec(event_bus_spec)
event_bus_spec.loader.exec_module(event_bus_module)

# Import the classes we need
EventBus = event_bus_module.EventBus
Event = event_bus_module.Event
EventTypes = event_bus_module.EventTypes
create_event = event_bus_module.create_event

# Import database client
db_spec = importlib.util.spec_from_file_location("dynamodb_client", "/app/shared/database/dynamodb_client.py")
db_module = importlib.util.module_from_spec(db_spec)
db_spec.loader.exec_module(db_module)

DynamoDBClient = db_module.LGProtectDynamoDBClient

# Import logger utilities
logger_spec = importlib.util.spec_from_file_location("logger", "/app/shared/utils/logger.py")
logger_module = importlib.util.module_from_spec(logger_spec)
logger_spec.loader.exec_module(logger_module)
setup_logging = logger_module.setup_logging

# Import discovery engines
from engines.discovery_factory import get_discovery_factory
from utils.service_enablement_integration import get_service_enablement_integration

logger = structlog.get_logger(__name__)

# Enterprise Multi-Account Configuration
MAX_WORKERS = 15
TIMEOUT_SECONDS = 30
MAX_RETRIES = 3

# Thread-safe global statistics for enterprise scanning
lock = threading.Lock()
scan_stats = {
    "total_api_calls": 0,
    "successful_calls": 0,
    "failed_calls": 0,
    "accounts_processed": 0,
    "regions_processed": 0,
    "services_checked": 0
}

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
            return True
            
        except Exception as e:
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
            logger.warning(f"Could not fetch enabled regions: {str(e)}")
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

def load_service_mapping():
    """Load enhanced service mapping and extract global services configuration"""
    global GLOBAL_SERVICES
    
    # Try enhanced mapping first, fallback to basic mapping
    mapping_file = Path(__file__).parent / "config" / "enhanced_service_mapping.json"
    fallback_mapping_file = Path(__file__).parent / "config" / "service_enablement_mapping.json"
    
    try:
        with open(mapping_file, 'r') as f:
            mapping = json.load(f)
            logger.info(f"Successfully loaded enhanced service mapping from {mapping_file.name}")
            
            # Extract global services and their default regions
            GLOBAL_SERVICES = {}
            for service_name, config in mapping.items():
                if config.get('scope') == 'global':
                    # Global services default to us-east-1
                    GLOBAL_SERVICES[service_name] = 'us-east-1'
            
            logger.info(f"Identified {len(GLOBAL_SERVICES)} global services: {', '.join(GLOBAL_SERVICES.keys())}")
            logger.info(f"Regional services: {len(mapping) - len(GLOBAL_SERVICES)}")
            
            return mapping
            
    except FileNotFoundError:
        logger.warning(f"Enhanced service mapping file not found: {mapping_file}")
        logger.info("Falling back to basic service mapping")
        
        try:
            with open(fallback_mapping_file, 'r') as f:
                mapping = json.load(f)
                logger.info(f"Successfully loaded basic service mapping from {fallback_mapping_file.name}")
                
                # Extract global services and their default regions
                GLOBAL_SERVICES = {}
                for service_name, config in mapping.items():
                    if config.get('scope') == 'global':
                        # Global services default to us-east-1
                        GLOBAL_SERVICES[service_name] = 'us-east-1'
                
                logger.info(f"Identified {len(GLOBAL_SERVICES)} global services: {', '.join(GLOBAL_SERVICES.keys())}")
                logger.info(f"Regional services: {len(mapping) - len(GLOBAL_SERVICES)}")
                
                return mapping
                
        except FileNotFoundError:
            logger.error(f"Service mapping file not found: {fallback_mapping_file}")
            logger.info("Please ensure service_enablement_mapping.json exists in the inventory directory")
            raise FileNotFoundError(f"Required service mapping file not found: {fallback_mapping_file}")
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in service mapping file: {e}")
            logger.info(f"Please check the JSON syntax in {fallback_mapping_file}")
            raise
        except Exception as e:
            logger.error(f"Error loading service mapping: {e}")
            raise
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in enhanced service mapping file: {e}")
        logger.info(f"Please check the JSON syntax in {mapping_file}")
        raise
    except Exception as e:
        logger.error(f"Error loading enhanced service mapping: {e}")
        raise

def get_enhanced_client(session, client_type, region):
    """Get enhanced AWS client with enterprise configuration"""
    # Use proper scope-based region selection
    if client_type in GLOBAL_SERVICES:
        region = GLOBAL_SERVICES[client_type]
    
    from botocore.config import Config
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
        logger.warning(f"Could not parse resource info for {service_name}: {str(e)}")
        
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

def extract_enhanced_resource_info(response, service_config, service_name, region, account_id):
    """Enhanced resource extraction that handles multiple resource types per service"""
    try:
        if not response or not service_config:
            return 0, []
        
        all_resources = []
        resource_types = service_config.get('resource_types', {})
        
        # If no resource_types defined, fall back to basic extraction
        if not resource_types:
            # Extract basic configuration for backward compatibility
            resource_identifier = service_config.get('resource_identifier', 'id')
            count_field = service_config.get('count_field', '')
            return extract_resource_info(response, resource_identifier, count_field, service_name)
        
        # Process each resource type defined in the service configuration
        for resource_type_name, resource_config in resource_types.items():
            try:
                count_field = resource_config.get('count_field')
                resource_identifier = resource_config.get('resource_identifier', 'id')
                arn_format = resource_config.get('arn_format')
                
                if not count_field:
                    logger.warning(f"No count_field defined for resource type {resource_type_name} in {service_name}")
                    continue
                
                # Extract resources for this specific type
                resources = extract_resources_by_type(
                    response, count_field, resource_identifier, 
                    service_name, resource_type_name, arn_format,
                    region, account_id
                )
                
                all_resources.extend(resources)
                
            except Exception as e:
                logger.warning(f"Failed to extract {resource_type_name} resources for {service_name}: {str(e)}")
                continue
        
        return len(all_resources), all_resources
        
    except Exception as e:
        logger.warning(f"Could not parse enhanced resource info for {service_name}: {str(e)}")
        return 0, []

def extract_resources_by_type(response, count_field, resource_identifier, service_name, 
                            resource_type_name, arn_format, region, account_id):
    """Extract resources for a specific resource type"""
    resources = []
    
    try:
        # Parse the count_field to navigate the response structure
        if count_field.endswith('[*]'):
            # Handle array fields like "TableNames[*]", "QueueUrls[*]", etc.
            field_name = count_field.replace('[*]', '')
            if field_name in response and isinstance(response[field_name], list):
                # Direct array of strings (like TableNames, QueueUrls)
                for item in response[field_name]:
                    if isinstance(item, str):
                        resource_info = create_resource_info(
                            item, service_name, resource_type_name, 
                            resource_identifier, arn_format, region, account_id
                        )
                        resources.append(resource_info)
                    elif isinstance(item, dict) and resource_identifier in item:
                        # Object with identifier field
                        resource_info = create_resource_info(
                            item[resource_identifier], service_name, resource_type_name,
                            resource_identifier, arn_format, region, account_id, item
                        )
                        resources.append(resource_info)
                
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
                        return []
            
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
                            resource_info = create_resource_info(
                                identifier_value, service_name, resource_type_name,
                                resource_identifier, arn_format, region, account_id, item
                            )
                            resources.append(resource_info)
                    elif isinstance(item, str):
                        # Simple string value
                        resource_info = create_resource_info(
                            item, service_name, resource_type_name,
                            resource_identifier, arn_format, region, account_id
                        )
                        resources.append(resource_info)
        
        elif count_field in response:
            # Direct field access like "DetectorIds", "StreamNames"
            data = response[count_field]
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, str):
                        resource_info = create_resource_info(
                            item, service_name, resource_type_name,
                            resource_identifier, arn_format, region, account_id
                        )
                        resources.append(resource_info)
                    elif isinstance(item, dict) and resource_identifier in item:
                        resource_info = create_resource_info(
                            item[resource_identifier], service_name, resource_type_name,
                            resource_identifier, arn_format, region, account_id, item
                        )
                        resources.append(resource_info)
        
        # Handle special cases for services with complex nested structures
        if service_name == 'ec2' and 'Reservations' in response:
            # EC2 instances are nested in Reservations
            for reservation in response['Reservations']:
                if 'Instances' in reservation:
                    for instance in reservation['Instances']:
                        if 'InstanceId' in instance:
                            resource_info = create_resource_info(
                                instance['InstanceId'], service_name, 'instance',
                                'InstanceId', arn_format, region, account_id, instance
                            )
                            resources.append(resource_info)
        
        elif service_name == 'cloudfront' and 'DistributionList' in response:
            # CloudFront distributions
            dist_list = response['DistributionList']
            if 'Items' in dist_list:
                for item in dist_list['Items']:
                    if 'Id' in item:
                        resource_info = create_resource_info(
                            item['Id'], service_name, 'distribution',
                            'Id', arn_format, region, account_id, item
                        )
                        resources.append(resource_info)
        
        elif service_name == 'wafv2':
            # WAFv2 needs Scope parameter
            if 'WebACLs' in response:
                for acl in response['WebACLs']:
                    if 'Id' in acl:
                        resource_info = create_resource_info(
                            acl['Id'], service_name, 'web_acl',
                            'Id', arn_format, region, account_id, acl
                        )
                        resources.append(resource_info)
        
        return resources
        
    except Exception as e:
        logger.warning(f"Could not parse resource info for {service_name} {resource_type_name}: {str(e)}")
        return []

def create_resource_info(identifier, service_name, resource_type_name, resource_identifier, 
                        arn_format, region, account_id, full_item=None):
    """Create a standardized resource info dictionary"""
    resource_info = {
        'identifier': identifier,
        'service': service_name,
        'type': resource_type_name,
        'resource_identifier': resource_identifier,
        'region': region,
        'account_id': account_id
    }
    
    # Generate ARN if format is provided
    if arn_format:
        try:
            # Replace placeholders in ARN format
            arn = arn_format.replace('{resource_id}', str(identifier))
            arn = arn.replace('{region}', region)
            arn = arn.replace('{account_id}', str(account_id))
            resource_info['arn'] = arn
        except Exception as e:
            logger.warning(f"Failed to generate ARN for {service_name} {identifier}: {str(e)}")
    
    # Add additional useful fields if available
    if full_item and isinstance(full_item, dict):
        common_fields = ['Name', 'State', 'Status', 'CreatedTime', 'LaunchTime', 'InstanceType']
        for field in common_fields:
            if field in full_item:
                resource_info[field.lower()] = full_item[field]
        
        # Add tags if present
        if 'Tags' in full_item and isinstance(full_item['Tags'], list):
            resource_info['tags'] = full_item['Tags']
    
    return resource_info

def check_service_in_account_region(account_info, service_name, region, error_logger, service_mapping):
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
        
        # Extract configuration from enhanced mapping
        client_type = service_config.get('client_type', service_name)
        check_function = service_config.get('check_function')
        scope = service_config.get('scope', 'regional')
        regions = service_config.get('regions', [])
        category = service_config.get('category', 'unknown')
        
        # Check if this region is supported for this service
        if regions and region not in regions and region != 'global':
            return {
                'service': service_name,
                'region': region,
                'account_id': account_id,
                'enabled': False,
                'error': f'Region {region} not supported for service {service_name}',
                'functions_checked': 0,
                'functions_successful': 0,
                'resource_count': 0,
                'resources': []
            }
        
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
                    resource_count, resources = extract_enhanced_resource_info(
                        response, service_config, service_name, region, account_id
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
            'category': category,
            'resource_count': resource_count,
            'resources': resources,
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

# Global services will be loaded dynamically from service mapping
GLOBAL_SERVICES = {}
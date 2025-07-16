#!/usr/bin/env python3
"""
Enhanced Resource Extraction for LG-Protect Inventory System

Supports multiple resource types per service, ARN generation, and comprehensive
resource discovery using the enhanced service mapping configuration.
"""

import boto3
import json
import re
import os
from typing import Dict, List, Any, Optional, Tuple
from botocore.exceptions import ClientError, NoCredentialsError
import structlog

logger = structlog.get_logger(__name__)

class EnhancedResourceExtractor:
    """
    Enhanced resource extractor supporting multiple resource types per service
    with ARN generation and comprehensive discovery capabilities.
    """
    
    def __init__(self, mapping_file: Optional[str] = None):
        """
        Initialize the enhanced resource extractor
        
        Args:
            mapping_file: Path to the enhanced service mapping JSON file
        """
        self.mapping_file = mapping_file or "config/enhanced_service_mapping.json"
        self.service_mapping = self._load_enhanced_mapping()
        self.session = boto3.Session()
        
    def _load_enhanced_mapping(self) -> Dict[str, Any]:
        """Load the enhanced service mapping configuration"""
        try:
            # Try multiple possible paths
            possible_paths = [
                self.mapping_file,
                f"backend/services/inventory-service/{self.mapping_file}",
                f"src/{self.mapping_file}",
                f"config/{self.mapping_file}"
            ]
            
            for mapping_path in possible_paths:
                if os.path.exists(mapping_path):
                    with open(mapping_path, 'r') as f:
                        return json.load(f)
            
            # If not found, try relative to current working directory
            cwd = os.getcwd()
            relative_path = os.path.join(cwd, self.mapping_file)
            if os.path.exists(relative_path):
                with open(relative_path, 'r') as f:
                    return json.load(f)
            
            logger.error(f"Enhanced mapping file not found in any of the expected locations")
            return {}
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in mapping file: {e}")
            return {}
    
    def _get_account_id(self) -> str:
        """Get the current AWS account ID"""
        try:
            sts = self.session.client('sts')
            response = sts.get_caller_identity()
            return response['Account']
        except Exception as e:
            logger.warning(f"Could not get account ID: {e}")
            return "unknown"
    
    def _parse_count_field(self, response: Dict[str, Any], count_field: str) -> List[str]:
        """
        Parse a count field expression to extract resource identifiers
        
        Args:
            response: API response from AWS
            count_field: Field expression like "Reservations[*].Instances[*].InstanceId"
        
        Returns:
            List of resource identifiers
        """
        try:
            # Handle simple field access
            if '.' not in count_field or '[*]' not in count_field:
                if count_field in response:
                    return response[count_field] if isinstance(response[count_field], list) else [response[count_field]]
                return []
            
            # Handle nested field access with wildcards
            parts = count_field.split('.')
            current = response
            
            for part in parts:
                if part == '[*]':
                    if isinstance(current, list):
                        # Continue with the next part for each item
                        if len(parts) > parts.index(part) + 1:
                            next_part = parts[parts.index(part) + 1]
                            result = []
                            for item in current:
                                if isinstance(item, dict) and next_part in item:
                                    result.append(item[next_part])
                            return result
                        else:
                            return current
                    else:
                        return []
                elif part in current:
                    current = current[part]
                else:
                    return []
            
            if isinstance(current, list):
                # Convert all items to strings for consistency
                return [str(item) for item in current]
            else:
                return [str(current)]
            
        except Exception as e:
            logger.error(f"Error parsing count field {count_field}: {e}")
            return []
    
    def _generate_arn(self, arn_format: str, resource_id: str, region: str, account_id: str) -> str:
        """
        Generate ARN for a resource using the format template
        
        Args:
            arn_format: ARN format template
            resource_id: Resource identifier
            region: AWS region
            account_id: AWS account ID
        
        Returns:
            Generated ARN string
        """
        try:
            return arn_format.format(
                region=region,
                account_id=account_id,
                resource_id=resource_id
            )
        except Exception as e:
            logger.error(f"Error generating ARN for {resource_id}: {e}")
            return f"arn:aws:unknown:{region}:{account_id}:{resource_id}"
    
    def extract_resources_for_service(self, service_name: str, region: str = 'us-east-1') -> Dict[str, Any]:
        """
        Extract resources for a specific service using enhanced mapping
        
        Args:
            service_name: AWS service name (e.g., 'ec2', 's3')
            region: AWS region to scan
        
        Returns:
            Dictionary containing extracted resources with counts and ARNs
        """
        if service_name not in self.service_mapping:
            logger.warning(f"Service {service_name} not found in enhanced mapping")
            return {'error': 'Service not configured', 'total': 0}
        
        service_config = self.service_mapping[service_name]
        client_type = service_config.get('client_type', service_name)
        check_function = service_config.get('check_function')
        resource_types = service_config.get('resource_types', {})
        
        if not check_function:
            logger.warning(f"No check function configured for {service_name}")
            return {'error': 'No check function configured', 'total': 0}
        
        try:
            # Create client
            if service_config.get('scope') == 'global':
                client = self.session.client(client_type)
            else:
                client = self.session.client(client_type, region_name=region)
            
            # Get account ID for ARN generation
            account_id = self._get_account_id()
            
            # Call the check function
            method = getattr(client, check_function)
            response = method()
            
            extracted_resources = {
                'service': service_name,
                'region': region,
                'scope': service_config.get('scope', 'regional'),
                'category': service_config.get('category', 'unknown'),
                'resource_types': {},
                'total_resources': 0,
                'arns': []
            }
            
            # Extract each resource type
            for resource_type, config in resource_types.items():
                count_field = config.get('count_field', '')
                resource_identifier = config.get('resource_identifier', '')
                arn_format = config.get('arn_format', '')
                
                if count_field:
                    resource_ids = self._parse_count_field(response, count_field)
                    count = len(resource_ids)
                    
                    # Generate ARNs for each resource
                    arns = []
                    for resource_id in resource_ids:
                        if arn_format and resource_id:
                            arn = self._generate_arn(arn_format, resource_id, region, account_id)
                            arns.append(arn)
                    
                    extracted_resources['resource_types'][resource_type] = {
                        'count': count,
                        'resource_ids': resource_ids,
                        'arns': arns
                    }
                    extracted_resources['total_resources'] += count
                    extracted_resources['arns'].extend(arns)
            
            return extracted_resources
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            logger.warning(f"Client error for {service_name}: {error_code}")
            return {
                'service': service_name,
                'region': region,
                'error': error_code,
                'total_resources': 0
            }
        except Exception as e:
            logger.error(f"Error extracting resources for {service_name}: {e}")
            return {
                'service': service_name,
                'region': region,
                'error': str(e),
                'total_resources': 0
            }
    
    def extract_all_resources(self, region: str = 'us-east-1', services: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Extract resources for all configured services
        
        Args:
            region: AWS region to scan
            services: List of specific services to scan (if None, scans all)
        
        Returns:
            Dictionary containing results for all services
        """
        if services is None:
            services = list(self.service_mapping.keys())
        
        results = {
            'region': region,
            'services_scanned': len(services),
            'total_resources': 0,
            'services': {},
            'summary': {
                'by_category': {},
                'by_scope': {'global': 0, 'regional': 0},
                'top_services': []
            }
        }
        
        for service_name in services:
            logger.info(f"Extracting resources for {service_name}")
            service_result = self.extract_resources_for_service(service_name, region)
            results['services'][service_name] = service_result
            
            if 'total_resources' in service_result:
                results['total_resources'] += service_result['total_resources']
                
                # Update category summary
                category = service_result.get('category', 'unknown')
                if category not in results['summary']['by_category']:
                    results['summary']['by_category'][category] = 0
                results['summary']['by_category'][category] += service_result['total_resources']
                
                # Update scope summary
                scope = service_result.get('scope', 'regional')
                results['summary']['by_scope'][scope] += service_result['total_resources']
        
        # Generate top services list
        service_counts = [
            (name, data.get('total_resources', 0)) 
            for name, data in results['services'].items()
            if 'error' not in data
        ]
        results['summary']['top_services'] = sorted(
            service_counts, 
            key=lambda x: x[1], 
            reverse=True
        )[:10]
        
        return results

def enhanced_extract_resources(service_name: str, region: str = 'us-east-1') -> Dict[str, Any]:
    """
    Convenience function for extracting resources for a single service
    
    Args:
        service_name: AWS service name
        region: AWS region
    
    Returns:
        Dictionary containing extracted resources
    """
    extractor = EnhancedResourceExtractor()
    return extractor.extract_resources_for_service(service_name, region)

def enhanced_extract_all_resources(region: str = 'us-east-1', services: Optional[List[str]] = None) -> Dict[str, Any]:
    """
    Convenience function for extracting resources for all services
    
    Args:
        region: AWS region
        services: List of specific services to scan
    
    Returns:
        Dictionary containing results for all services
    """
    extractor = EnhancedResourceExtractor()
    return extractor.extract_all_resources(region, services) 
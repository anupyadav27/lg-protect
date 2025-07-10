#!/usr/bin/env python3
"""
cis_4.0_aws - apigateway_restapi_public_with_authorizer

Ensure API Gateway REST API with public access has proper authorization
"""

import sys
import os
import json
from typing import Dict, List, Any

# Add the core-engine path to sys.path to import compliance_engine
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from compliance_engine import (
    ComplianceEngine,
    setup_command_line_interface,
    save_results,
    exit_with_status
)

def load_compliance_metadata(function_name: str) -> dict:
    """Load compliance metadata including risk level and recommendation from JSON."""
    try:
        # Path to compliance_checks.json relative to functions_list directory
        compliance_json_path = os.path.join(
            os.path.dirname(__file__), 
            '..', '..', 
            'compliance_checks.json'
        )
        
        with open(compliance_json_path, 'r') as f:
            compliance_data = json.load(f)
        
        # Find the specific compliance entry for this function
        for entry in compliance_data:
            if entry.get('Function Name') == function_name:
                return {
                    'compliance_name': entry.get('Compliance Name', ''),
                    'function_name': entry.get('Function Name', ''),
                    'id': entry.get('ID', ''),
                    'name': entry.get('Name', ''),
                    'description': entry.get('Description', ''),
                    'api_function': entry.get('API function', ''),
                    'user_function': entry.get('user function', ''),
                    'risk_level': entry.get('Risk Level', 'MEDIUM'),
                    'recommendation': entry.get('Recommendation', 'Review and remediate as needed')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'cis_4.0_aws',
        'function_name': 'apigateway_restapi_public_with_authorizer',
        'id': 'api-gateway-public-auth',
        'name': 'API Gateway REST API Public with Authorizer',
        'description': 'Ensure API Gateway REST API with public access has proper authorization',
        'api_function': 'client = boto3.client(\'apigateway\')',
        'user_function': 'get_rest_apis(), get_authorizers(), get_resources(), get_method()',
        'risk_level': 'HIGH',
        'recommendation': 'Configure proper authorization for publicly accessible API Gateway methods'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('apigateway_restapi_public_with_authorizer')

def apigateway_restapi_public_with_authorizer_check(apigateway_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for apigateway_restapi_public_with_authorizer.
    
    Args:
        apigateway_client: Boto3 apigateway client (auto-created by framework)
        region (str): AWS region (auto-managed by framework)
        profile (str): AWS profile name (auto-managed by framework)
        logger: Logger instance (auto-configured by framework)
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    try:
        # Get all REST APIs
        response = apigateway_client.get_rest_apis()
        rest_apis = response.get('items', [])
        
        if not rest_apis:
            # No REST APIs found - create a finding indicating no resources
            findings.append({
                'region': region,
                'profile': profile,
                'resource_type': 'AWS::ApiGateway::RestApi',
                'resource_id': 'No APIs found',
                'status': 'COMPLIANT',
                'compliance_status': 'PASS',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                'recommendation': COMPLIANCE_DATA.get('recommendation', 'Configure proper authorization for publicly accessible API Gateway methods'),
                'details': {
                    'message': 'No REST APIs found in this region'
                }
            })
            return findings
        
        for api in rest_apis:
            api_id = api.get('id')
            api_name = api.get('name', 'Unknown')
            endpoint_configuration = api.get('endpointConfiguration', {})
            endpoint_types = endpoint_configuration.get('types', [])
            
            # Skip private APIs as they are not publicly accessible
            if 'PRIVATE' in endpoint_types and len(endpoint_types) == 1:
                findings.append({
                    'region': region,
                    'profile': profile,
                    'resource_type': 'AWS::ApiGateway::RestApi',
                    'resource_id': api_id,
                    'status': 'COMPLIANT',
                    'compliance_status': 'PASS',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Configure proper authorization for publicly accessible API Gateway methods'),
                    'details': {
                        'api_name': api_name,
                        'api_id': api_id,
                        'endpoint_types': endpoint_types,
                        'reason': 'API is private, not publicly accessible'
                    }
                })
                continue
            
            try:
                # Get authorizers for this API
                authorizers_response = apigateway_client.get_authorizers(restApiId=api_id)
                authorizers = authorizers_response.get('items', [])
                has_authorizers = len(authorizers) > 0
                
                # Get resources for this API
                resources_response = apigateway_client.get_resources(restApiId=api_id)
                resources = resources_response.get('items', [])
                
                public_methods_without_auth = []
                total_methods = 0
                
                for resource in resources:
                    resource_id = resource.get('id')
                    resource_path = resource.get('path', '/')
                    resource_methods = resource.get('resourceMethods', {})
                    
                    for method_name, method_info in resource_methods.items():
                        if method_name == 'OPTIONS':
                            continue  # Skip OPTIONS methods as they're typically for CORS
                        
                        total_methods += 1
                        
                        try:
                            # Get method details
                            method_response = apigateway_client.get_method(
                                restApiId=api_id,
                                resourceId=resource_id,
                                httpMethod=method_name
                            )
                            
                            # Check authorization type
                            authorization_type = method_response.get('authorizationType', 'NONE')
                            authorizer_id = method_response.get('authorizerId')
                            api_key_required = method_response.get('apiKeyRequired', False)
                            
                            # Method is considered unprotected if it has no authorization
                            is_unprotected = (
                                authorization_type == 'NONE' and 
                                not authorizer_id and 
                                not api_key_required
                            )
                            
                            if is_unprotected:
                                public_methods_without_auth.append({
                                    'resource_path': resource_path,
                                    'method': method_name,
                                    'authorization_type': authorization_type,
                                    'api_key_required': api_key_required
                                })
                                
                        except Exception as method_error:
                            logger.warning(f"Could not get method details for {method_name} on {resource_path}: {method_error}")
                
                # Determine compliance status
                is_compliant = len(public_methods_without_auth) == 0
                
                findings.append({
                    'region': region,
                    'profile': profile,
                    'resource_type': 'AWS::ApiGateway::RestApi',
                    'resource_id': api_id,
                    'status': 'COMPLIANT' if is_compliant else 'NON_COMPLIANT',
                    'compliance_status': 'PASS' if is_compliant else 'FAIL',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Configure proper authorization for publicly accessible API Gateway methods'),
                    'details': {
                        'api_name': api_name,
                        'api_id': api_id,
                        'endpoint_types': endpoint_types,
                        'has_authorizers': has_authorizers,
                        'total_methods': total_methods,
                        'unprotected_methods_count': len(public_methods_without_auth),
                        'unprotected_methods': public_methods_without_auth[:10]  # Limit to first 10 for readability
                    }
                })
                
            except Exception as api_error:
                logger.error(f"Error checking API {api_id}: {api_error}")
                findings.append({
                    'region': region,
                    'profile': profile,
                    'resource_type': 'AWS::ApiGateway::RestApi',
                    'resource_id': api_id,
                    'status': 'ERROR',
                    'compliance_status': 'ERROR',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Configure proper authorization for publicly accessible API Gateway methods'),
                    'error': str(api_error),
                    'details': {
                        'api_name': api_name
                    }
                })
        
    except Exception as e:
        logger.error(f"Error in apigateway_restapi_public_with_authorizer check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'AWS::ApiGateway::RestApi',
            'resource_id': 'Unknown',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Configure proper authorization for publicly accessible API Gateway methods'),
            'error': str(e)
        })
        
    return findings

def apigateway_restapi_public_with_authorizer(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=apigateway_restapi_public_with_authorizer_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = apigateway_restapi_public_with_authorizer(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

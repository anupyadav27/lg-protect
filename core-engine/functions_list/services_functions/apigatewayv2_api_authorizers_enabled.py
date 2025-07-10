#!/usr/bin/env python3
"""
aws_well_architected_framework_security_pillar_aws - apigatewayv2_api_authorizers_enabled

Ensure API Gateway V2 APIs have authorizers enabled for secure access control
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
                    'recommendation': entry.get('Recommendation', 'Enable authorizers for API Gateway V2 APIs')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'aws_well_architected_framework_security_pillar_aws',
        'function_name': 'apigatewayv2_api_authorizers_enabled',
        'id': 'SEC-01',
        'name': 'API Gateway V2 APIs should have authorizers enabled',
        'description': 'Ensure API Gateway V2 APIs have authorizers enabled for secure access control',
        'api_function': 'client = boto3.client(\'apigatewayv2\')',
        'user_function': 'get_apis(), get_authorizers()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Enable authorizers for API Gateway V2 APIs'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('apigatewayv2_api_authorizers_enabled')

def apigatewayv2_api_authorizers_enabled_check(apigatewayv2_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for apigatewayv2_api_authorizers_enabled.
    
    Args:
        apigatewayv2_client: Boto3 API Gateway V2 client (auto-created by framework)
        region (str): AWS region (auto-managed by framework)
        profile (str): AWS profile name (auto-managed by framework)
        logger: Logger instance (auto-configured by framework)
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    try:
        # Get all API Gateway V2 APIs
        response = apigatewayv2_client.get_apis()
        apis = response.get('Items', [])
        
        if not apis:
            logger.info(f"No API Gateway V2 APIs found in region {region}")
            return findings
        
        for api in apis:
            api_id = api['ApiId']
            api_name = api.get('Name', 'Unknown')
            protocol_type = api.get('ProtocolType', 'Unknown')
            
            try:
                # Get authorizers for this API
                authorizers_response = apigatewayv2_client.get_authorizers(ApiId=api_id)
                authorizers = authorizers_response.get('Items', [])
                
                # Get routes for this API to check if they use authorizers
                routes_response = apigatewayv2_client.get_routes(ApiId=api_id)
                routes = routes_response.get('Items', [])
                
                # Check if API has authorizers configured
                has_authorizers = len(authorizers) > 0
                
                # Check routes for authorization
                routes_with_auth = []
                routes_without_auth = []
                
                for route in routes:
                    route_key = route.get('RouteKey', 'Unknown')
                    authorization_type = route.get('AuthorizationType', 'NONE')
                    authorizer_id = route.get('AuthorizerId')
                    
                    if authorization_type != 'NONE' or authorizer_id:
                        routes_with_auth.append({
                            'route_key': route_key,
                            'authorization_type': authorization_type,
                            'authorizer_id': authorizer_id
                        })
                    else:
                        routes_without_auth.append({
                            'route_key': route_key,
                            'authorization_type': authorization_type
                        })
                
                # Determine compliance status
                if has_authorizers and len(routes_without_auth) == 0:
                    status = 'COMPLIANT'
                    compliance_status = 'PASS'
                elif not has_authorizers or len(routes_without_auth) > 0:
                    status = 'NON_COMPLIANT' 
                    compliance_status = 'FAIL'
                else:
                    status = 'COMPLIANT'
                    compliance_status = 'PASS'
                
                authorizer_details = []
                for auth in authorizers:
                    authorizer_details.append({
                        'authorizer_id': auth.get('AuthorizerId'),
                        'name': auth.get('Name'),
                        'authorizer_type': auth.get('AuthorizerType'),
                        'identity_source': auth.get('IdentitySource', []),
                        'authorizer_uri': auth.get('AuthorizerUri')
                    })
                
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'API Gateway V2 API',
                    'resource_id': api_id,
                    'status': status,
                    'compliance_status': compliance_status,
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable authorizers for API Gateway V2 APIs'),
                    'details': {
                        'api_id': api_id,
                        'api_name': api_name,
                        'protocol_type': protocol_type,
                        'has_authorizers': has_authorizers,
                        'authorizers_count': len(authorizers),
                        'total_routes': len(routes),
                        'routes_with_auth': len(routes_with_auth),
                        'routes_without_auth': len(routes_without_auth),
                        'authorizers': authorizer_details,
                        'unauthorized_routes': routes_without_auth[:5]  # Limit to first 5
                    }
                }
                
                findings.append(finding)
                
            except Exception as e:
                logger.error(f"Error checking authorizers for API {api_id}: {e}")
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'API Gateway V2 API',
                    'resource_id': api_id,
                    'status': 'ERROR',
                    'compliance_status': 'ERROR',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable authorizers for API Gateway V2 APIs'),
                    'error': f"Error checking API authorizers: {str(e)}"
                }
                findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in apigatewayv2_api_authorizers_enabled check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'API Gateway V2 API',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable authorizers for API Gateway V2 APIs'),
            'error': str(e)
        })
        
    return findings

def apigatewayv2_api_authorizers_enabled(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=apigatewayv2_api_authorizers_enabled_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = apigatewayv2_api_authorizers_enabled(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

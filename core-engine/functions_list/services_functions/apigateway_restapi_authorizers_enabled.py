#!/usr/bin/env python3
"""
cis_4.0_aws - apigateway_restapi_authorizers_enabled

Ensure API Gateway REST API has authorizers enabled
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
        'function_name': 'apigateway_restapi_authorizers_enabled',
        'id': 'api-gateway-authorizers',
        'name': 'API Gateway REST API Authorizers',
        'description': 'Ensure API Gateway REST API has authorizers enabled',
        'api_function': 'client = boto3.client(\'apigateway\')',
        'user_function': 'get_rest_apis(), get_authorizers()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Configure authorizers for API Gateway REST APIs'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('apigateway_restapi_authorizers_enabled')

def apigateway_restapi_authorizers_enabled_check(apigateway_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for apigateway_restapi_authorizers_enabled.
    
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
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                'recommendation': COMPLIANCE_DATA.get('recommendation', 'Configure authorizers for API Gateway REST APIs'),
                'details': {
                    'message': 'No REST APIs found in this region'
                }
            })
            return findings
        
        for api in rest_apis:
            api_id = api.get('id')
            api_name = api.get('name', 'Unknown')
            
            try:
                # Get authorizers for this API
                authorizers_response = apigateway_client.get_authorizers(restApiId=api_id)
                authorizers = authorizers_response.get('items', [])
                
                authorizer_details = []
                for authorizer in authorizers:
                    authorizer_details.append({
                        'id': authorizer.get('id'),
                        'name': authorizer.get('name'),
                        'type': authorizer.get('type'),
                        'provider_arns': authorizer.get('providerARNs', []),
                        'auth_type': authorizer.get('authType')
                    })
                
                has_authorizers = len(authorizers) > 0
                
                findings.append({
                    'region': region,
                    'profile': profile,
                    'resource_type': 'AWS::ApiGateway::RestApi',
                    'resource_id': api_id,
                    'status': 'COMPLIANT' if has_authorizers else 'NON_COMPLIANT',
                    'compliance_status': 'PASS' if has_authorizers else 'FAIL',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Configure authorizers for API Gateway REST APIs'),
                    'details': {
                        'api_name': api_name,
                        'api_id': api_id,
                        'authorizers_count': len(authorizers),
                        'has_authorizers': has_authorizers,
                        'authorizers': authorizer_details
                    }
                })
                
            except Exception as api_error:
                logger.error(f"Error checking authorizers for API {api_id}: {api_error}")
                findings.append({
                    'region': region,
                    'profile': profile,
                    'resource_type': 'AWS::ApiGateway::RestApi',
                    'resource_id': api_id,
                    'status': 'ERROR',
                    'compliance_status': 'ERROR',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Configure authorizers for API Gateway REST APIs'),
                    'error': str(api_error),
                    'details': {
                        'api_name': api_name
                    }
                })
        
    except Exception as e:
        logger.error(f"Error in apigateway_restapi_authorizers_enabled check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'AWS::ApiGateway::RestApi',
            'resource_id': 'Unknown',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Configure authorizers for API Gateway REST APIs'),
            'error': str(e)
        })
        
    return findings

def apigateway_restapi_authorizers_enabled(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=apigateway_restapi_authorizers_enabled_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = apigateway_restapi_authorizers_enabled(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

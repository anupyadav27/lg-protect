#!/usr/bin/env python3
"""
cis_4.0_aws - apigateway_restapi_logging_enabled

Ensure API Gateway REST API logging is enabled
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
        'function_name': 'apigateway_restapi_logging_enabled',
        'id': 'api-gateway-logging',
        'name': 'API Gateway REST API Logging',
        'description': 'Ensure API Gateway REST API logging is enabled',
        'api_function': 'client = boto3.client(\'apigateway\')',
        'user_function': 'get_rest_apis(), get_stage()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Enable logging for API Gateway REST API stages'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('apigateway_restapi_logging_enabled')

def apigateway_restapi_logging_enabled_check(apigateway_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for apigateway_restapi_logging_enabled.
    
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
                'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable logging for API Gateway REST API stages'),
                'details': {
                    'message': 'No REST APIs found in this region'
                }
            })
            return findings
        
        for api in rest_apis:
            api_id = api.get('id')
            api_name = api.get('name', 'Unknown')
            
            try:
                # Get stages for this API
                stages_response = apigateway_client.get_stages(restApiId=api_id)
                stages = stages_response.get('item', [])
                
                if not stages:
                    # API has no stages
                    findings.append({
                        'region': region,
                        'profile': profile,
                        'resource_type': 'AWS::ApiGateway::RestApi',
                        'resource_id': api_id,
                        'status': 'NON_COMPLIANT',
                        'compliance_status': 'FAIL',
                        'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                        'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable logging for API Gateway REST API stages'),
                        'details': {
                            'api_name': api_name,
                            'issue': 'No stages found for this API'
                        }
                    })
                    continue
                
                # Check each stage for logging configuration
                for stage in stages:
                    stage_name = stage.get('stageName')
                    access_log_settings = stage.get('accessLogSettings', {})
                    method_settings = stage.get('methodSettings', {})
                    
                    # Check if access logging is enabled
                    access_log_enabled = bool(access_log_settings.get('destinationArn'))
                    
                    # Check if execution logging is enabled for any method
                    execution_log_enabled = False
                    for method_key, method_config in method_settings.items():
                        if method_config.get('loggingLevel', 'OFF') != 'OFF':
                            execution_log_enabled = True
                            break
                    
                    # Stage is compliant if either access logging or execution logging is enabled
                    is_compliant = access_log_enabled or execution_log_enabled
                    
                    findings.append({
                        'region': region,
                        'profile': profile,
                        'resource_type': 'AWS::ApiGateway::Stage',
                        'resource_id': f"{api_id}/{stage_name}",
                        'status': 'COMPLIANT' if is_compliant else 'NON_COMPLIANT',
                        'compliance_status': 'PASS' if is_compliant else 'FAIL',
                        'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                        'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable logging for API Gateway REST API stages'),
                        'details': {
                            'api_name': api_name,
                            'api_id': api_id,
                            'stage_name': stage_name,
                            'access_log_enabled': access_log_enabled,
                            'execution_log_enabled': execution_log_enabled,
                            'access_log_destination': access_log_settings.get('destinationArn', 'Not configured')
                        }
                    })
                    
            except Exception as stage_error:
                logger.error(f"Error checking stages for API {api_id}: {stage_error}")
                findings.append({
                    'region': region,
                    'profile': profile,
                    'resource_type': 'AWS::ApiGateway::RestApi',
                    'resource_id': api_id,
                    'status': 'ERROR',
                    'compliance_status': 'ERROR',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable logging for API Gateway REST API stages'),
                    'error': str(stage_error),
                    'details': {
                        'api_name': api_name
                    }
                })
        
    except Exception as e:
        logger.error(f"Error in apigateway_restapi_logging_enabled check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'AWS::ApiGateway::RestApi',
            'resource_id': 'Unknown',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable logging for API Gateway REST API stages'),
            'error': str(e)
        })
        
    return findings

def apigateway_restapi_logging_enabled(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=apigateway_restapi_logging_enabled_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = apigateway_restapi_logging_enabled(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

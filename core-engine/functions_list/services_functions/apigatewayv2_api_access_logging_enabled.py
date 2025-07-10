#!/usr/bin/env python3
"""
iso27001_2022_aws - apigatewayv2_api_access_logging_enabled

Logs that record activities, exceptions, faults and other relevant events should be produced, stored, protected and analysed.
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
    """Load compliance metadata from compliance_checks.json."""
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
        'compliance_name': 'iso27001_2022_aws',
        'function_name': 'apigatewayv2_api_access_logging_enabled',
        'id': 'APIGateway.9',
        'name': 'Access logging should be configured for API Gateway V2 Stages',
        'description': 'Logs that record activities, exceptions, faults and other relevant events should be produced, stored, protected and analysed.',
        'api_function': 'client1 = boto3.client(\'apigateway\'), client2=boto3.client(\'wafv2\')',
        'user_function': 'get_apis(), get_stages()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Enable access logging for API Gateway V2 stages'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('apigatewayv2_api_access_logging_enabled')

def apigatewayv2_api_access_logging_enabled_check(apigatewayv2_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for apigatewayv2_api_access_logging_enabled.
    
    Args:
        apigatewayv2_client: Boto3 apigatewayv2 service client (auto-created by framework)
        region (str): AWS region (auto-managed by framework)
        profile (str): AWS profile name (auto-managed by framework)
        logger: Logger instance (auto-configured by framework)
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    try:
        # Get all API Gateway V2 APIs
        apis_response = apigatewayv2_client.get_apis()
        apis = apis_response.get('Items', [])
        
        if not apis:
            # No APIs found - create a single finding indicating no resources
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'API Gateway V2',
                'resource_id': f'no-apis-{region}',
                'status': 'COMPLIANT',
                'compliance_status': 'PASS',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable access logging for API Gateway V2 stages'),
                'details': {
                    'message': 'No API Gateway V2 APIs found in this region',
                    'api_count': 0
                }
            }
            findings.append(finding)
            return findings
        
        # Check each API for access logging
        for api in apis:
            api_id = api.get('ApiId')
            api_name = api.get('Name', 'Unknown')
            protocol_type = api.get('ProtocolType', 'Unknown')
            
            try:
                # Get stages for this API
                stages_response = apigatewayv2_client.get_stages(ApiId=api_id)
                stages = stages_response.get('Items', [])
                
                if not stages:
                    # API has no stages
                    finding = {
                        'region': region,
                        'profile': profile,
                        'resource_type': 'API Gateway V2 API',
                        'resource_id': api_id,
                        'status': 'NON_COMPLIANT',
                        'compliance_status': 'FAIL',
                        'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                        'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable access logging for API Gateway V2 stages'),
                        'details': {
                            'api_name': api_name,
                            'protocol_type': protocol_type,
                            'stages_count': 0,
                            'message': 'API has no stages configured'
                        }
                    }
                    findings.append(finding)
                    continue
                
                # Check each stage for access logging
                for stage in stages:
                    stage_name = stage.get('StageName')
                    access_log_settings = stage.get('AccessLogSettings')
                    
                    # Check if access logging is configured
                    if access_log_settings and access_log_settings.get('DestinationArn'):
                        status = 'COMPLIANT'
                        compliance_status = 'PASS'
                        message = f'Access logging is enabled for stage {stage_name}'
                    else:
                        status = 'NON_COMPLIANT'
                        compliance_status = 'FAIL'
                        message = f'Access logging is not enabled for stage {stage_name}'
                    
                    finding = {
                        'region': region,
                        'profile': profile,
                        'resource_type': 'API Gateway V2 Stage',
                        'resource_id': f'{api_id}/{stage_name}',
                        'status': status,
                        'compliance_status': compliance_status,
                        'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                        'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable access logging for API Gateway V2 stages'),
                        'details': {
                            'api_id': api_id,
                            'api_name': api_name,
                            'protocol_type': protocol_type,
                            'stage_name': stage_name,
                            'access_logging_enabled': bool(access_log_settings and access_log_settings.get('DestinationArn')),
                            'destination_arn': access_log_settings.get('DestinationArn') if access_log_settings else None,
                            'message': message
                        }
                    }
                    findings.append(finding)
                    
            except Exception as e:
                logger.error(f"Error checking stages for API {api_id}: {e}")
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'API Gateway V2 API',
                    'resource_id': api_id,
                    'status': 'ERROR',
                    'compliance_status': 'ERROR',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable access logging for API Gateway V2 stages'),
                    'error': str(e),
                    'details': {
                        'api_name': api_name,
                        'protocol_type': protocol_type,
                        'message': f'Error checking stages for API {api_id}'
                    }
                }
                findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in apigatewayv2_api_access_logging_enabled check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'API Gateway V2',
            'resource_id': f'error-{region}',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable access logging for API Gateway V2 stages'),
            'error': str(e)
        })
        
    return findings

def apigatewayv2_api_access_logging_enabled(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=apigatewayv2_api_access_logging_enabled_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = apigatewayv2_api_access_logging_enabled(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

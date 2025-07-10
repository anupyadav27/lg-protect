#!/usr/bin/env python3
"""
iso27001_2022_aws - appsync_field_level_logging_enabled

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
        'compliance_name': 'iso27001_2022_aws',
        'function_name': 'appsync_field_level_logging_enabled',
        'id': 'A.12.4',
        'name': 'Logging and Monitoring',
        'description': 'Logs that record activities, exceptions, faults and other relevant events should be produced, stored, protected and analysed.',
        'api_function': 'client = boto3.client("appsync")',
        'user_function': 'list_graphql_apis()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Enable field-level logging for all AppSync GraphQL APIs'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('appsync_field_level_logging_enabled')

def appsync_field_level_logging_enabled_check(appsync_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for appsync_field_level_logging_enabled.
    
    Args:
        appsync_client: Boto3 appsync client (auto-created by framework)
        region (str): AWS region (auto-managed by framework)
        profile (str): AWS profile name (auto-managed by framework)
        logger: Logger instance (auto-configured by framework)
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    try:
        # Get all GraphQL APIs
        paginator = appsync_client.get_paginator('list_graphql_apis')
        apis = []
        
        for page in paginator.paginate():
            apis.extend(page.get('graphqlApis', []))
        
        if not apis:
            # No GraphQL APIs found
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'AppSync GraphQL API',
                'resource_id': f'no-apis-{region}',
                'status': 'COMPLIANT',
                'compliance_status': 'PASS',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                'recommendation': 'No AppSync GraphQL APIs found',
                'details': {
                    'apis_count': 0,
                    'apis_with_field_logging': 0,
                    'apis_without_field_logging': 0
                }
            }
            findings.append(finding)
            return findings
        
        # Check each API for field-level logging
        for api in apis:
            api_id = api.get('apiId', '')
            api_name = api.get('name', '')
            
            try:
                # Get detailed API information including logging configuration
                response = appsync_client.get_graphql_api(apiId=api_id)
                api_details = response.get('graphqlApi', {})
                
                log_config = api_details.get('logConfig', {})
                field_log_level = log_config.get('fieldLogLevel', '')
                exclude_verbose_content = log_config.get('excludeVerboseContent', True)
                cloudwatch_logs_role_arn = log_config.get('cloudWatchLogsRoleArn', '')
                
                api_info = {
                    'api_id': api_id,
                    'api_name': api_name,
                    'authentication_type': api_details.get('authenticationType', ''),
                    'field_log_level': field_log_level,
                    'exclude_verbose_content': exclude_verbose_content,
                    'cloudwatch_logs_role_arn': cloudwatch_logs_role_arn,
                    'created_date': api_details.get('createdDate'),
                    'uris': api_details.get('uris', {})
                }
                
                # Check if field-level logging is enabled
                # Field-level logging is considered enabled if fieldLogLevel is set to 'ALL' or 'ERROR'
                if field_log_level in ['ALL', 'ERROR']:
                    finding = {
                        'region': region,
                        'profile': profile,
                        'resource_type': 'AppSync GraphQL API',
                        'resource_id': api_id,
                        'status': 'COMPLIANT',
                        'compliance_status': 'PASS',
                        'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                        'recommendation': 'Field-level logging is properly configured',
                        'details': api_info
                    }
                else:
                    finding = {
                        'region': region,
                        'profile': profile,
                        'resource_type': 'AppSync GraphQL API',
                        'resource_id': api_id,
                        'status': 'NON_COMPLIANT',
                        'compliance_status': 'FAIL',
                        'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                        'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable field-level logging for AppSync GraphQL API'),
                        'details': api_info
                    }
                
                findings.append(finding)
                
            except Exception as e:
                logger.warning(f"Error checking API {api_id}: {e}")
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'AppSync GraphQL API',
                    'resource_id': api_id,
                    'status': 'ERROR',
                    'compliance_status': 'ERROR',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                    'recommendation': 'Unable to determine logging configuration',
                    'error': str(e),
                    'details': {
                        'api_id': api_id,
                        'api_name': api_name,
                        'error_details': str(e)
                    }
                }
                findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in appsync_field_level_logging_enabled check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'AppSync GraphQL API',
            'status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Review and remediate as needed'),
            'error': str(e)
        })
        
    return findings

def appsync_field_level_logging_enabled(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=appsync_field_level_logging_enabled_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = appsync_field_level_logging_enabled(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

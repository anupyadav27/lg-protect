#!/usr/bin/env python3
"""
iso27001_2022_aws - athena_workgroup_logging_enabled

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
        'function_name': 'athena_workgroup_logging_enabled',
        'id': 'A.12.4',
        'name': 'Logging and Monitoring',
        'description': 'Logs that record activities, exceptions, faults and other relevant events should be produced, stored, protected and analysed.',
        'api_function': 'client = boto3.client(\'athena\')',
        'user_function': 'list_work_groups(), get_work_group(WorkGroup=\'string\')',
        'risk_level': 'MEDIUM',
        'recommendation': 'Enable logging for Athena workgroups to maintain audit trails'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('athena_workgroup_logging_enabled')

def athena_workgroup_logging_enabled_check(athena_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for athena_workgroup_logging_enabled.
    
    Args:
        athena_client: Boto3 athena service client (auto-created by framework)
        region (str): AWS region (auto-managed by framework)
        profile (str): AWS profile name (auto-managed by framework)
        logger: Logger instance (auto-configured by framework)
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    try:
        # Get all Athena workgroups
        paginator = athena_client.get_paginator('list_work_groups')
        workgroups = []
        
        for page in paginator.paginate():
            workgroups.extend(page.get('WorkGroups', []))
        
        if not workgroups:
            # No workgroups found - create a single finding indicating no resources
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'Athena Workgroup',
                'resource_id': f'no-workgroups-{region}',
                'status': 'COMPLIANT',
                'compliance_status': 'PASS',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable logging for Athena workgroups'),
                'details': {
                    'message': 'No Athena workgroups found in this region',
                    'workgroup_count': 0
                }
            }
            findings.append(finding)
            return findings
        
        # Check each workgroup for logging configuration
        for workgroup_summary in workgroups:
            workgroup_name = workgroup_summary.get('Name')
            workgroup_state = workgroup_summary.get('State', 'Unknown')
            
            try:
                # Get detailed workgroup configuration
                workgroup_response = athena_client.get_work_group(WorkGroup=workgroup_name)
                workgroup_config = workgroup_response.get('WorkGroup', {}).get('Configuration', {})
                
                # Check if result configuration exists and has logging
                result_config = workgroup_config.get('ResultConfiguration', {})
                output_location = result_config.get('OutputLocation')
                
                # Check for CloudWatch logs configuration
                publish_cloudwatch_metrics = workgroup_config.get('PublishCloudWatchMetrics', False)
                bytes_scanned_cutoff = workgroup_config.get('BytesScannedCutoffPerQuery')
                
                # Determine if logging is properly configured
                logging_enabled = False
                logging_details = {}
                
                if output_location:
                    logging_enabled = True
                    logging_details['output_location'] = output_location
                    logging_details['result_encryption'] = result_config.get('EncryptionConfiguration', {})
                
                if publish_cloudwatch_metrics:
                    logging_details['cloudwatch_metrics'] = True
                
                # Check compliance
                if logging_enabled or publish_cloudwatch_metrics:
                    status = 'COMPLIANT'
                    compliance_status = 'PASS'
                    message = f'Logging is enabled for workgroup {workgroup_name}'
                else:
                    status = 'NON_COMPLIANT'
                    compliance_status = 'FAIL'
                    message = f'Logging is not properly configured for workgroup {workgroup_name}'
                
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'Athena Workgroup',
                    'resource_id': workgroup_name,
                    'status': status,
                    'compliance_status': compliance_status,
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable logging for Athena workgroups'),
                    'details': {
                        'workgroup_name': workgroup_name,
                        'workgroup_state': workgroup_state,
                        'output_location': output_location,
                        'publish_cloudwatch_metrics': publish_cloudwatch_metrics,
                        'bytes_scanned_cutoff': bytes_scanned_cutoff,
                        'logging_enabled': logging_enabled,
                        'logging_details': logging_details,
                        'message': message
                    }
                }
                findings.append(finding)
                
            except Exception as e:
                logger.error(f"Error checking workgroup {workgroup_name}: {e}")
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'Athena Workgroup',
                    'resource_id': workgroup_name,
                    'status': 'ERROR',
                    'compliance_status': 'ERROR',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable logging for Athena workgroups'),
                    'error': str(e),
                    'details': {
                        'workgroup_name': workgroup_name,
                        'workgroup_state': workgroup_state,
                        'message': f'Error checking workgroup {workgroup_name}'
                    }
                }
                findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in athena_workgroup_logging_enabled check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'Athena Workgroup',
            'resource_id': f'error-{region}',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable logging for Athena workgroups'),
            'error': str(e)
        })
        
    return findings

def athena_workgroup_logging_enabled(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=athena_workgroup_logging_enabled_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = athena_workgroup_logging_enabled(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

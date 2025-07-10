#!/usr/bin/env python3
"""
soc2_aws - datasync_task_logging_enabled

Measures Current Usage - The use of the system components is measured to establish a baseline for capacity management and to use when evaluating the risk of impaired availability due to capacity constraints.
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
                    'recommendation': entry.get('Recommendation', 'Enable logging for DataSync tasks to monitor operations')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'soc2_aws',
        'function_name': 'datasync_task_logging_enabled',
        'id': 'cc_a_1_1',
        'name': 'A1.2 The entity authorizes, designs, develops or acquires, implements, operates, approves, maintains, and monitors environmental protections, software, data back-up processes, and recovery infrastructure to meet its objectives',
        'description': 'Measures Current Usage - The use of the system components is measured to establish a baseline for capacity management and to use when evaluating the risk of impaired availability due to capacity constraints.',
        'api_function': 'client=boto3.client(\'datasync\')',
        'user_function': 'describe_task()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Enable logging for DataSync tasks to monitor operations'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('datasync_task_logging_enabled')

def datasync_task_logging_enabled_check(datasync_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for datasync_task_logging_enabled.
    
    Args:
        datasync_client: Boto3 DataSync client (auto-created by framework)
        region (str): AWS region (auto-managed by framework)
        profile (str): AWS profile name (auto-managed by framework)
        logger: Logger instance (auto-configured by framework)
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    try:
        # List all DataSync tasks
        paginator = datasync_client.get_paginator('list_tasks')
        page_iterator = paginator.paginate()
        
        all_tasks = []
        for page in page_iterator:
            all_tasks.extend(page.get('Tasks', []))
        
        if not all_tasks:
            # No DataSync tasks found
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'DataSync',
                'resource_id': f'datasync-check-{region}',
                'status': 'COMPLIANT',
                'compliance_status': 'PASS',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                'recommendation': 'No DataSync tasks found',
                'details': {
                    'total_tasks': 0
                }
            }
            findings.append(finding)
            return findings
        
        # Check each task for logging configuration
        for task in all_tasks:
            task_arn = task.get('TaskArn', '')
            task_name = task.get('Name', task_arn.split('/')[-1] if task_arn else 'unknown')
            
            try:
                # Describe the task to get detailed configuration
                task_details = datasync_client.describe_task(TaskArn=task_arn)
                
                # Check for CloudWatch log group configuration
                cloud_watch_log_group_arn = task_details.get('CloudWatchLogGroupArn')
                
                # Check task options for logging
                options = task_details.get('Options', {})
                log_level = options.get('LogLevel', 'OFF')
                
                # Determine if logging is enabled
                logging_enabled = bool(cloud_watch_log_group_arn) and log_level != 'OFF'
                
                if logging_enabled:
                    status = 'COMPLIANT'
                    compliance_status = 'PASS'
                    recommendation = 'DataSync task has logging properly configured'
                else:
                    status = 'NON_COMPLIANT'
                    compliance_status = 'FAIL'
                    recommendation = 'Enable CloudWatch logging for DataSync task to monitor operations'
                
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'DataSync Task',
                    'resource_id': task_arn,
                    'status': status,
                    'compliance_status': compliance_status,
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                    'recommendation': recommendation,
                    'details': {
                        'task_name': task_name,
                        'task_arn': task_arn,
                        'logging_enabled': logging_enabled,
                        'cloudwatch_log_group_arn': cloud_watch_log_group_arn,
                        'log_level': log_level,
                        'task_status': task_details.get('Status', 'unknown'),
                        'source_location_arn': task_details.get('SourceLocationArn'),
                        'destination_location_arn': task_details.get('DestinationLocationArn')
                    }
                }
                
                findings.append(finding)
                
            except Exception as e:
                logger.warning(f"Error describing DataSync task {task_arn}: {e}")
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'DataSync Task',
                    'resource_id': task_arn,
                    'status': 'ERROR',
                    'compliance_status': 'ERROR',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                    'recommendation': 'Unable to check logging configuration due to access error',
                    'error': str(e),
                    'details': {
                        'task_name': task_name,
                        'task_arn': task_arn
                    }
                }
                findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in datasync_task_logging_enabled check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'DataSync',
            'resource_id': f'datasync-error-{region}',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable logging for DataSync tasks to monitor operations'),
            'error': str(e)
        })
        
    return findings

def datasync_task_logging_enabled(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=datasync_task_logging_enabled_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = datasync_task_logging_enabled(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

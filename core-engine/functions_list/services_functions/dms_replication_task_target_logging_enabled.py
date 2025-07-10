#!/usr/bin/env python3
"""
iso27001_2022_aws - dms_replication_task_target_logging_enabled

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
                    'recommendation': entry.get('Recommendation', 'Enable target logging for DMS replication tasks')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'iso27001_2022_aws',
        'function_name': 'dms_replication_task_target_logging_enabled',
        'id': 'ISO-27001-2022-A.12.4',
        'name': 'Logging and Monitoring',
        'description': 'Logs that record activities, exceptions, faults and other relevant events should be produced, stored, protected and analysed.',
        'api_function': 'client=boto3.client(\'dms\')',
        'user_function': 'describe_replication_tasks()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Enable target logging for DMS replication tasks to track data migration activities'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('dms_replication_task_target_logging_enabled')

def dms_replication_task_target_logging_enabled_check(dms_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for dms_replication_task_target_logging_enabled.
    
    Args:
        dms_client: Boto3 DMS client (auto-created by framework)
        region (str): AWS region (auto-managed by framework)
        profile (str): AWS profile name (auto-managed by framework)
        logger: Logger instance (auto-configured by framework)
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    try:
        # Get all DMS replication tasks
        paginator = dms_client.get_paginator('describe_replication_tasks')
        
        for page in paginator.paginate():
            replication_tasks = page.get('ReplicationTasks', [])
            
            if not replication_tasks:
                continue
                
            for task in replication_tasks:
                task_identifier = task.get('ReplicationTaskIdentifier', 'unknown')
                task_arn = task.get('ReplicationTaskArn', 'unknown')
                status = task.get('Status', 'unknown')
                migration_type = task.get('MigrationType', 'unknown')
                
                # Check task settings for target logging
                task_settings_json = task.get('ReplicationTaskSettings', '{}')
                
                target_logging_enabled = False
                try:
                    if task_settings_json:
                        task_settings = json.loads(task_settings_json)
                        logging_settings = task_settings.get('Logging', {})
                        
                        # Check for target component logging
                        enable_logging = logging_settings.get('EnableLogging', False)
                        log_components = logging_settings.get('LogComponents', [])
                        
                        # Look for target-related logging components
                        target_components = ['TARGET_LOAD', 'TARGET_APPLY', 'TASK_MANAGER']
                        
                        if enable_logging:
                            for component in log_components:
                                component_id = component.get('Id', '')
                                severity = component.get('Severity', 'LOGGER_SEVERITY_OFF')
                                
                                if (component_id in target_components and 
                                    severity != 'LOGGER_SEVERITY_OFF'):
                                    target_logging_enabled = True
                                    break
                    
                except json.JSONDecodeError as json_error:
                    logger.warning(f"Could not parse task settings JSON for {task_identifier}: {json_error}")
                
                # Determine compliance status
                if target_logging_enabled:
                    status_result = 'COMPLIANT'
                    compliance_status = 'PASS'
                    risk_level = 'LOW'
                    recommendation = 'DMS replication task has target logging properly enabled'
                else:
                    status_result = 'NON_COMPLIANT'
                    compliance_status = 'FAIL'
                    risk_level = COMPLIANCE_DATA.get('risk_level', 'MEDIUM')
                    recommendation = COMPLIANCE_DATA.get('recommendation', 'Enable target logging for this DMS replication task')
                
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'DMS Replication Task',
                    'resource_id': task_identifier,
                    'status': status_result,
                    'compliance_status': compliance_status,
                    'risk_level': risk_level,
                    'recommendation': recommendation,
                    'details': {
                        'replication_task_identifier': task_identifier,
                        'replication_task_arn': task_arn,
                        'task_status': status,
                        'migration_type': migration_type,
                        'target_logging_enabled': target_logging_enabled,
                        'is_compliant': target_logging_enabled,
                        'security_note': 'Target logging helps track data migration activities and troubleshoot issues'
                    }
                }
                
                findings.append(finding)
        
        # If no replication tasks found, create an informational finding
        if not findings:
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'DMS Replication Task',
                'resource_id': f'no-tasks-{region}',
                'status': 'COMPLIANT',
                'compliance_status': 'PASS',
                'risk_level': 'LOW',
                'recommendation': 'No DMS replication tasks found in this region',
                'details': {
                    'tasks_count': 0,
                    'message': 'No DMS replication tasks found to check for target logging'
                }
            }
            findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in dms_replication_task_target_logging_enabled check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'DMS Replication Task',
            'resource_id': f'error-check-{region}',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable target logging for DMS replication tasks'),
            'error': str(e)
        })
        
    return findings

def dms_replication_task_target_logging_enabled(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=dms_replication_task_target_logging_enabled_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = dms_replication_task_target_logging_enabled(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

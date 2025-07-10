#!/usr/bin/env python3
"""
pci_3.2.1_aws - stepfunctions_statemachine_logging_enabled

It is critical to have a process or system that links user access to system components accessed. This system generates audit logs and provides the ability to trace back suspicious activity to a specific user.
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
        'compliance_name': 'pci_3.2.1_aws',
        'function_name': 'stepfunctions_statemachine_logging_enabled',
        'id': 'SF-001',
        'name': 'Step Functions State Machine Logging',
        'description': 'It is critical to have a process or system that links user access to system components accessed. This system generates audit logs and provides the ability to trace back suspicious activity to a specific user.',
        'api_function': 'client=boto3.client("stepfunctions")',
        'user_function': 'list_state_machines(), describe_state_machine()',
        'risk_level': 'HIGH',
        'recommendation': 'Enable logging for all Step Functions state machines to maintain audit trails'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('stepfunctions_statemachine_logging_enabled')

def stepfunctions_statemachine_logging_enabled_check(stepfunctions_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for stepfunctions_statemachine_logging_enabled.
    
    Args:
        stepfunctions_client: Boto3 Step Functions client (auto-created by framework)
        region (str): AWS region (auto-managed by framework)
        profile (str): AWS profile name (auto-managed by framework)
        logger: Logger instance (auto-configured by framework)
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    try:
        # List all state machines
        paginator = stepfunctions_client.get_paginator('list_state_machines')
        
        for page in paginator.paginate():
            state_machines = page.get('stateMachines', [])
            
            if not state_machines:
                logger.info(f"No Step Functions state machines found in region {region}")
                continue
            
            for sm in state_machines:
                sm_arn = sm.get('stateMachineArn', 'Unknown')
                sm_name = sm.get('name', 'Unknown')
                sm_type = sm.get('type', 'Unknown')
                
                try:
                    # Get detailed state machine information
                    sm_response = stepfunctions_client.describe_state_machine(
                        stateMachineArn=sm_arn
                    )
                    
                    logging_configuration = sm_response.get('loggingConfiguration', {})
                    tracing_configuration = sm_response.get('tracingConfiguration', {})
                    
                    # Check logging configuration
                    log_level = logging_configuration.get('level', 'OFF')
                    include_execution_data = logging_configuration.get('includeExecutionData', False)
                    destinations = logging_configuration.get('destinations', [])
                    
                    # Check if logging is properly configured
                    has_logging = log_level != 'OFF'
                    has_destinations = len(destinations) > 0
                    
                    # Check tracing
                    tracing_enabled = tracing_configuration.get('enabled', False)
                    
                    # Determine compliance - logging should be enabled with at least one destination
                    is_compliant = has_logging and has_destinations
                    
                    if is_compliant:
                        # Logging properly configured - COMPLIANT
                        finding = {
                            'region': region,
                            'profile': profile,
                            'resource_type': 'StepFunctions_StateMachine',
                            'resource_id': f"{sm_name} ({sm_arn})",
                            'status': 'COMPLIANT',
                            'compliance_status': 'PASS',
                            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Maintain logging configuration'),
                            'details': {
                                'state_machine_name': sm_name,
                                'state_machine_arn': sm_arn,
                                'state_machine_type': sm_type,
                                'log_level': log_level,
                                'include_execution_data': include_execution_data,
                                'destinations_count': len(destinations),
                                'destinations': [dest.get('cloudWatchLogsLogGroup', {}).get('logGroupArn', 'Unknown') for dest in destinations],
                                'tracing_enabled': tracing_enabled
                            }
                        }
                    else:
                        # Logging not properly configured - NON_COMPLIANT
                        issues = []
                        if not has_logging:
                            issues.append('Logging is disabled (level: OFF)')
                        if not has_destinations:
                            issues.append('No log destinations configured')
                        
                        finding = {
                            'region': region,
                            'profile': profile,
                            'resource_type': 'StepFunctions_StateMachine',
                            'resource_id': f"{sm_name} ({sm_arn})",
                            'status': 'NON_COMPLIANT',
                            'compliance_status': 'FAIL',
                            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                            'recommendation': 'Enable logging and configure log destinations for this state machine',
                            'details': {
                                'state_machine_name': sm_name,
                                'state_machine_arn': sm_arn,
                                'state_machine_type': sm_type,
                                'log_level': log_level,
                                'include_execution_data': include_execution_data,
                                'destinations_count': len(destinations),
                                'tracing_enabled': tracing_enabled,
                                'issues': issues
                            }
                        }
                    
                    findings.append(finding)
                    
                except Exception as sm_error:
                    logger.error(f"Error describing state machine {sm_arn}: {sm_error}")
                    finding = {
                        'region': region,
                        'profile': profile,
                        'resource_type': 'StepFunctions_StateMachine',
                        'resource_id': f"{sm_name} ({sm_arn})",
                        'status': 'ERROR',
                        'compliance_status': 'ERROR',
                        'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                        'recommendation': 'Review state machine configuration',
                        'error': str(sm_error),
                        'details': {
                            'state_machine_name': sm_name,
                            'state_machine_arn': sm_arn,
                            'state_machine_type': sm_type
                        }
                    }
                    findings.append(finding)
        
        if not findings:
            logger.info(f"No Step Functions state machines found in region {region}")
        
    except Exception as e:
        logger.error(f"Error in stepfunctions_statemachine_logging_enabled check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'StepFunctions_StateMachine',
            'status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Review Step Functions configuration'),
            'error': str(e)
        })
        
    return findings

def stepfunctions_statemachine_logging_enabled(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=stepfunctions_statemachine_logging_enabled_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = stepfunctions_statemachine_logging_enabled(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

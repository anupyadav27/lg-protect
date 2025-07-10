#!/usr/bin/env python3
"""
pci_4.0_aws - cloudwatch_alarm_actions_alarm_state_configured

Checks whether CloudWatch alarms with the given metric name have the specified settings
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
        'compliance_name': 'pci_4.0_aws',
        'function_name': 'cloudwatch_alarm_actions_alarm_state_configured',
        'id': 'PCI.CloudWatch.1',
        'name': 'CloudWatch alarm actions should be configured',
        'description': 'Checks whether CloudWatch alarms with the given metric name have the specified settings',
        'api_function': 'client = boto3.client(\'cloudwatch\')',
        'user_function': 'describe_alarms()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Configure alarm actions for CloudWatch alarms'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('cloudwatch_alarm_actions_alarm_state_configured')

def cloudwatch_alarm_actions_alarm_state_configured_check(cloudwatch_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for cloudwatch_alarm_actions_alarm_state_configured.
    
    Args:
        cloudwatch_client: Boto3 CloudWatch client (auto-created by framework)
        region (str): AWS region (auto-managed by framework)
        profile (str): AWS profile name (auto-managed by framework)
        logger: Logger instance (auto-configured by framework)
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    try:
        # Get all CloudWatch alarms
        alarms = []
        paginator = cloudwatch_client.get_paginator('describe_alarms')
        
        for page in paginator.paginate():
            alarms.extend(page.get('MetricAlarms', []))
            alarms.extend(page.get('CompositeAlarms', []))
        
        if not alarms:
            # No alarms found - compliant by default
            findings.append({
                'region': region,
                'profile': profile,
                'resource_type': 'CloudWatch',
                'resource_id': f'no-alarms-{region}',
                'status': 'COMPLIANT',
                'compliance_status': 'PASS',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                'recommendation': 'No CloudWatch alarms found',
                'details': {
                    'alarm_count': 0,
                    'message': 'No CloudWatch alarms exist in this region'
                }
            })
            return findings
        
        for alarm in alarms:
            alarm_name = alarm.get('AlarmName', '')
            alarm_arn = alarm.get('AlarmArn', '')
            alarm_state = alarm.get('StateValue', '')
            
            # Check alarm actions for different states
            alarm_actions = alarm.get('AlarmActions', [])
            ok_actions = alarm.get('OKActions', [])
            insufficient_data_actions = alarm.get('InsufficientDataActions', [])
            
            # Check if alarm has actions configured
            has_alarm_actions = len(alarm_actions) > 0
            has_ok_actions = len(ok_actions) > 0
            has_insufficient_data_actions = len(insufficient_data_actions) > 0
            
            # An alarm should have at least alarm actions configured
            actions_properly_configured = has_alarm_actions
            
            # Check if actions are valid (not empty strings)
            valid_alarm_actions = [action for action in alarm_actions if action and action.strip()]
            valid_ok_actions = [action for action in ok_actions if action and action.strip()]
            valid_insufficient_data_actions = [action for action in insufficient_data_actions if action and action.strip()]
            
            has_valid_actions = len(valid_alarm_actions) > 0
            
            if has_valid_actions:
                status = 'COMPLIANT'
                compliance_status = 'PASS'
                recommendation = 'Alarm actions are properly configured'
            else:
                status = 'NON_COMPLIANT'
                compliance_status = 'FAIL'
                recommendation = COMPLIANCE_DATA.get('recommendation', 'Configure alarm actions for CloudWatch alarms')
            
            # Check action types
            action_types = _categorize_alarm_actions(valid_alarm_actions + valid_ok_actions + valid_insufficient_data_actions)
            
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'CloudWatch Alarm',
                'resource_id': alarm_name,
                'status': status,
                'compliance_status': compliance_status,
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                'recommendation': recommendation,
                'details': {
                    'alarm_name': alarm_name,
                    'alarm_arn': alarm_arn,
                    'alarm_state': alarm_state,
                    'alarm_actions': {
                        'alarm_state_actions': valid_alarm_actions,
                        'ok_state_actions': valid_ok_actions,
                        'insufficient_data_actions': valid_insufficient_data_actions
                    },
                    'action_counts': {
                        'alarm_actions': len(valid_alarm_actions),
                        'ok_actions': len(valid_ok_actions),
                        'insufficient_data_actions': len(valid_insufficient_data_actions)
                    },
                    'action_types': action_types,
                    'has_valid_actions': has_valid_actions
                }
            }
            
            findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in cloudwatch_alarm_actions_alarm_state_configured check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'CloudWatch',
            'resource_id': f'check-error-{region}',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Review and remediate as needed'),
            'error': str(e)
        })
        
    return findings

def _categorize_alarm_actions(actions: List[str]) -> Dict[str, int]:
    """
    Categorize alarm actions by type.
    
    Args:
        actions (List[str]): List of action ARNs
        
    Returns:
        Dict[str, int]: Count of each action type
    """
    action_types = {
        'sns': 0,
        'autoscaling': 0,
        'ec2': 0,
        'ssm': 0,
        'other': 0
    }
    
    for action in actions:
        if 'sns:' in action or ':sns:' in action:
            action_types['sns'] += 1
        elif 'autoscaling:' in action or ':autoscaling:' in action:
            action_types['autoscaling'] += 1
        elif 'ec2:' in action or ':ec2:' in action:
            action_types['ec2'] += 1
        elif 'ssm:' in action or ':ssm:' in action:
            action_types['ssm'] += 1
        else:
            action_types['other'] += 1
    
    return action_types

def cloudwatch_alarm_actions_alarm_state_configured(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=cloudwatch_alarm_actions_alarm_state_configured_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = cloudwatch_alarm_actions_alarm_state_configured(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

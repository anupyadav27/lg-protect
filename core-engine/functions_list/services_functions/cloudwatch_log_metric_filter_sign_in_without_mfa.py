#!/usr/bin/env python3
"""
cis_4.0_aws - cloudwatch_log_metric_filter_sign_in_without_mfa

Ensure a log metric filter and alarm exist for sign-in without MFA
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
                    'risk_level': entry.get('Risk Level', 'HIGH'),
                    'recommendation': entry.get('Recommendation', 'Review and remediate as needed')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'cis_4.0_aws',
        'function_name': 'cloudwatch_log_metric_filter_sign_in_without_mfa',
        'id': '4.3',
        'name': 'Ensure a log metric filter and alarm exist for sign-in without MFA',
        'description': 'Ensure a log metric filter and alarm exist for sign-in without MFA',
        'api_function': 'logs_client = boto3.client(\'logs\'), cw_client = boto3.client(\'cloudwatch\')',
        'user_function': 'describe_log_groups(), describe_metric_filters(), describe_alarms()',
        'risk_level': 'HIGH',
        'recommendation': 'Create log metric filter and alarm for sign-in without MFA'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('cloudwatch_log_metric_filter_sign_in_without_mfa')

def cloudwatch_log_metric_filter_sign_in_without_mfa_check(logs_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for cloudwatch_log_metric_filter_sign_in_without_mfa.
    
    Args:
        logs_client: Boto3 CloudWatch Logs client (auto-created by framework)
        region (str): AWS region (auto-managed by framework)
        profile (str): AWS profile name (auto-managed by framework)
        logger: Logger instance (auto-configured by framework)
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    try:
        # Create CloudWatch client for alarm checking
        import boto3
        session = boto3.Session(profile_name=profile if profile != 'default' else None)
        cloudwatch_client = session.client('cloudwatch', region_name=region)
        
        # Get all log groups
        log_groups = []
        paginator = logs_client.get_paginator('describe_log_groups')
        
        for page in paginator.paginate():
            log_groups.extend(page.get('logGroups', []))
        
        if not log_groups:
            findings.append({
                'region': region,
                'profile': profile,
                'resource_type': 'CloudWatch Logs',
                'resource_id': f'no-log-groups-{region}',
                'status': 'NON_COMPLIANT',
                'compliance_status': 'FAIL',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                'recommendation': COMPLIANCE_DATA.get('recommendation', 'Create log metric filter and alarm for sign-in without MFA'),
                'details': {
                    'issue': 'No CloudWatch log groups found',
                    'message': 'No log groups available for metric filter configuration'
                }
            })
            return findings
        
        # Check for CloudTrail log groups and metric filters for sign-in without MFA
        cloudtrail_log_groups = []
        mfa_signin_filters = []
        
        for log_group in log_groups:
            log_group_name = log_group.get('logGroupName', '')
            
            # Identify CloudTrail log groups (typically contain 'cloudtrail' in name)
            if 'cloudtrail' in log_group_name.lower():
                cloudtrail_log_groups.append(log_group_name)
                
                # Get metric filters for this log group
                try:
                    filters_response = logs_client.describe_metric_filters(
                        logGroupName=log_group_name
                    )
                    
                    metric_filters = filters_response.get('metricFilters', [])
                    
                    for metric_filter in metric_filters:
                        filter_pattern = metric_filter.get('filterPattern', '')
                        
                        # Check if filter pattern matches sign-in without MFA
                        if _check_mfa_signin_pattern(filter_pattern):
                            mfa_signin_filters.append({
                                'log_group': log_group_name,
                                'filter_name': metric_filter.get('filterName', ''),
                                'metric_name': metric_filter.get('metricTransformations', [{}])[0].get('metricName', ''),
                                'metric_namespace': metric_filter.get('metricTransformations', [{}])[0].get('metricNamespace', ''),
                                'filter_pattern': filter_pattern
                            })
                            
                except Exception as filter_error:
                    logger.warning(f"Error checking metric filters for {log_group_name}: {filter_error}")
                    continue
        
        # Check for alarms on the metric filters
        alarms_configured = []
        
        for filter_info in mfa_signin_filters:
            metric_name = filter_info.get('metric_name')
            metric_namespace = filter_info.get('metric_namespace')
            
            if metric_name and metric_namespace:
                try:
                    alarms_response = cloudwatch_client.describe_alarms(
                        MetricName=metric_name,
                        Namespace=metric_namespace
                    )
                    
                    alarms = alarms_response.get('MetricAlarms', [])
                    
                    for alarm in alarms:
                        alarms_configured.append({
                            'alarm_name': alarm.get('AlarmName', ''),
                            'alarm_arn': alarm.get('AlarmArn', ''),
                            'state': alarm.get('StateValue', ''),
                            'metric_name': metric_name,
                            'metric_namespace': metric_namespace
                        })
                        
                except Exception as alarm_error:
                    logger.warning(f"Error checking alarms for metric {metric_name}: {alarm_error}")
                    continue
        
        # Determine compliance status
        has_metric_filter = len(mfa_signin_filters) > 0
        has_alarm = len(alarms_configured) > 0
        
        if has_metric_filter and has_alarm:
            status = 'COMPLIANT'
            compliance_status = 'PASS'
            recommendation = 'Log metric filter and alarm for sign-in without MFA are properly configured'
        else:
            status = 'NON_COMPLIANT'
            compliance_status = 'FAIL'
            recommendation = COMPLIANCE_DATA.get('recommendation', 'Create log metric filter and alarm for sign-in without MFA')
        
        finding = {
            'region': region,
            'profile': profile,
            'resource_type': 'CloudWatch Monitoring',
            'resource_id': f'mfa-signin-monitoring-{region}',
            'status': status,
            'compliance_status': compliance_status,
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
            'recommendation': recommendation,
            'details': {
                'cloudtrail_log_groups': cloudtrail_log_groups,
                'mfa_signin_filters': mfa_signin_filters,
                'alarms_configured': alarms_configured,
                'has_metric_filter': has_metric_filter,
                'has_alarm': has_alarm,
                'total_log_groups': len(log_groups)
            }
        }
        
        findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in cloudwatch_log_metric_filter_sign_in_without_mfa check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'CloudWatch Monitoring',
            'resource_id': f'check-error-{region}',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Review and remediate as needed'),
            'error': str(e)
        })
        
    return findings

def _check_mfa_signin_pattern(filter_pattern: str) -> bool:
    """
    Check if the filter pattern matches sign-in without MFA monitoring.
    
    Args:
        filter_pattern (str): The CloudWatch Logs filter pattern
        
    Returns:
        bool: True if pattern matches sign-in without MFA, False otherwise
    """
    if not filter_pattern:
        return False
    
    pattern_lower = filter_pattern.lower()
    
    # Check for MFA-related patterns
    mfa_patterns = [
        'mfaused',
        'mfa_used',
        'multifactorauthenticationused',
        'multifactor',
        'mfaauthentication'
    ]
    
    # Check for sign-in related patterns
    signin_patterns = [
        'signin',
        'sign-in',
        'consolelogin',
        'eventname'
    ]
    
    # Must contain MFA checking and sign-in patterns
    has_mfa = any(mfa_pattern in pattern_lower for mfa_pattern in mfa_patterns)
    has_signin = any(signin_pattern in pattern_lower for signin_pattern in signin_patterns)
    
    # Common pattern: checking for ConsoleLogin events where MFA was not used
    has_console_login = 'consolelogin' in pattern_lower
    
    return (has_mfa and has_signin) or has_console_login

def cloudwatch_log_metric_filter_sign_in_without_mfa(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=cloudwatch_log_metric_filter_sign_in_without_mfa_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = cloudwatch_log_metric_filter_sign_in_without_mfa(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

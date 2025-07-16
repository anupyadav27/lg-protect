#!/usr/bin/env python3
"""
cis_4.0_aws - cloudwatch_log_metric_filter_and_alarm_for_aws_config_configuration_changes_enabled

Ensure AWS Config configuration changes are monitored
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
                    'recommendation': entry.get('Recommendation', 'Configure CloudWatch log metric filters and alarms for AWS Config configuration changes')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'cis_4.0_aws',
        'function_name': 'cloudwatch_log_metric_filter_and_alarm_for_aws_config_configuration_changes_enabled',
        'id': 'CIS-4.0-AWS-CONFIG-MONITOR',
        'name': 'AWS Config Configuration Changes Monitoring',
        'description': 'Ensure AWS Config configuration changes are monitored',
        'api_function': 'ct_client = boto3.client(\'cloudtrail\'), cw_client = boto3.client(\'cloudwatch\')',
        'user_function': 'describe_metric_filters(), describe_alarms(), lookup_events()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Configure CloudWatch log metric filters and alarms for AWS Config configuration changes'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('cloudwatch_log_metric_filter_and_alarm_for_aws_config_configuration_changes_enabled')

def cloudwatch_log_metric_filter_and_alarm_for_aws_config_configuration_changes_enabled_check(logs_client, cloudwatch_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for AWS Config configuration changes monitoring.
    
    Args:
        logs_client: Boto3 CloudWatch Logs client
        cloudwatch_client: Boto3 CloudWatch client
        region (str): AWS region
        profile (str): AWS profile name
        logger: Logger instance
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    # AWS Config-related API calls that should be monitored
    config_events_patterns = [
        '{ ($.eventSource = config.amazonaws.com) && (($.eventName = StopConfigurationRecorder) || ($.eventName = DeleteDeliveryChannel) || ($.eventName = PutDeliveryChannel) || ($.eventName = PutConfigurationRecorder)) }',
        '{ $.eventSource = "config.amazonaws.com" }',
        '{ ($.eventName = PutConfigurationRecorder) || ($.eventName = StopConfigurationRecorder) || ($.eventName = DeleteDeliveryChannel) || ($.eventName = PutDeliveryChannel) }'
    ]
    
    try:
        # Get all log groups
        log_groups_response = logs_client.describe_log_groups()
        log_groups = log_groups_response.get('logGroups', [])
        
        if not log_groups:
            findings.append({
                'region': region,
                'profile': profile,
                'resource_type': 'CloudWatchLogs',
                'resource_id': 'no-log-groups',
                'status': 'NON_COMPLIANT',
                'compliance_status': 'FAIL',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                'recommendation': 'Create CloudWatch log groups and configure CloudTrail to send logs for monitoring',
                'details': {
                    'issue': 'No CloudWatch log groups found',
                    'expected_patterns': config_events_patterns
                }
            })
            return findings
        
        # Check for metric filters that monitor AWS Config events
        config_metric_filters_found = []
        
        for log_group in log_groups:
            log_group_name = log_group.get('logGroupName')
            
            try:
                # Get metric filters for this log group
                filters_response = logs_client.describe_metric_filters(
                    logGroupName=log_group_name
                )
                
                metric_filters = filters_response.get('metricFilters', [])
                
                for metric_filter in metric_filters:
                    filter_pattern = metric_filter.get('filterPattern', '')
                    
                    # Check if the filter pattern matches AWS Config monitoring patterns
                    if any(config_pattern.replace(' ', '').lower() in filter_pattern.replace(' ', '').lower() 
                           for config_pattern in ['config.amazonaws.com', 'StopConfigurationRecorder', 
                                                'DeleteDeliveryChannel', 'PutDeliveryChannel', 
                                                'PutConfigurationRecorder']):
                        
                        metric_transformations = metric_filter.get('metricTransformations', [])
                        
                        for transformation in metric_transformations:
                            metric_name = transformation.get('metricName')
                            metric_namespace = transformation.get('metricNamespace')
                            
                            config_metric_filters_found.append({
                                'log_group_name': log_group_name,
                                'filter_name': metric_filter.get('filterName'),
                                'filter_pattern': filter_pattern,
                                'metric_name': metric_name,
                                'metric_namespace': metric_namespace
                            })
                            
            except Exception as e:
                logger.warning(f"Error checking metric filters for log group {log_group_name}: {e}")
                continue
        
        if not config_metric_filters_found:
            findings.append({
                'region': region,
                'profile': profile,
                'resource_type': 'CloudWatchMetricFilter',
                'resource_id': 'config-monitoring-missing',
                'status': 'NON_COMPLIANT',
                'compliance_status': 'FAIL',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                'recommendation': COMPLIANCE_DATA.get('recommendation', 'Configure CloudWatch log metric filters and alarms for AWS Config configuration changes'),
                'details': {
                    'issue': 'No metric filters found for AWS Config events monitoring',
                    'log_groups_checked': len(log_groups),
                    'expected_patterns': config_events_patterns
                }
            })
            return findings
        
        # Check for alarms associated with the metric filters
        alarms_found = []
        
        for metric_filter in config_metric_filters_found:
            metric_name = metric_filter.get('metric_name')
            metric_namespace = metric_filter.get('metric_namespace')
            
            try:
                # Get alarms for this metric
                alarms_response = cloudwatch_client.describe_alarms(
                    MetricName=metric_name,
                    Namespace=metric_namespace
                )
                
                alarms = alarms_response.get('MetricAlarms', [])
                
                for alarm in alarms:
                    alarms_found.append({
                        'alarm_name': alarm.get('AlarmName'),
                        'metric_name': metric_name,
                        'metric_namespace': metric_namespace,
                        'alarm_state': alarm.get('StateValue'),
                        'actions_enabled': alarm.get('ActionsEnabled', False),
                        'alarm_actions': alarm.get('AlarmActions', [])
                    })
                    
            except Exception as e:
                logger.warning(f"Error checking alarms for metric {metric_name}: {e}")
                continue
        
        if not alarms_found:
            # Metric filters exist but no alarms configured
            findings.append({
                'region': region,
                'profile': profile,
                'resource_type': 'CloudWatchAlarm',
                'resource_id': 'config-alarms-missing',
                'status': 'NON_COMPLIANT',
                'compliance_status': 'FAIL',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                'recommendation': 'Configure CloudWatch alarms for the existing AWS Config metric filters',
                'details': {
                    'issue': 'Metric filters exist but no associated alarms found',
                    'metric_filters_found': len(config_metric_filters_found),
                    'metric_filters': config_metric_filters_found
                }
            })
        else:
            # Both metric filters and alarms are configured
            findings.append({
                'region': region,
                'profile': profile,
                'resource_type': 'CloudWatchMonitoring',
                'resource_id': 'config-monitoring-configured',
                'status': 'COMPLIANT',
                'compliance_status': 'PASS',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                'recommendation': 'AWS Config monitoring is properly configured',
                'details': {
                    'metric_filters_found': len(config_metric_filters_found),
                    'alarms_found': len(alarms_found),
                    'metric_filters': config_metric_filters_found,
                    'alarms': alarms_found
                }
            })
        
    except Exception as e:
        logger.error(f"Error in cloudwatch_log_metric_filter_and_alarm_for_aws_config_configuration_changes_enabled check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'CloudWatchMonitoring',
            'resource_id': 'check-error',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Configure CloudWatch log metric filters and alarms for AWS Config configuration changes'),
            'error': str(e)
        })
        
    return findings

def cloudwatch_log_metric_filter_and_alarm_for_aws_config_configuration_changes_enabled(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=cloudwatch_log_metric_filter_and_alarm_for_aws_config_configuration_changes_enabled_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = cloudwatch_log_metric_filter_and_alarm_for_aws_config_configuration_changes_enabled(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

#!/usr/bin/env python3
"""
kisa_isms_p_2023_aws - cloudwatch_changes_to_vpcs_alarm_configured

The organization must define the types of logs, retention periods, and retention methods for user access records, system logs, and privilege grant records for information systems such as servers, applications, security systems, and network systems, and must securely retain and manage them to prevent tampering, theft, or loss.
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
        'compliance_name': 'kisa_isms_p_2023_aws',
        'function_name': 'cloudwatch_changes_to_vpcs_alarm_configured',
        'id': '2.9.4',
        'name': 'Log and Access Record Management',
        'description': 'The organization must define the types of logs, retention periods, and retention methods for user access records, system logs, and privilege grant records for information systems such as servers, applications, security systems, and network systems, and must securely retain and manage them to prevent tampering, theft, or loss.',
        'api_function': 'logs_client = boto3.client("logs"), cw_client = boto3.client("cloudwatch")',
        'user_function': 'describe_log_groups(), describe_metric_filters(), describe_alarms()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Configure CloudWatch alarms to monitor VPC changes'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('cloudwatch_changes_to_vpcs_alarm_configured')

def cloudwatch_changes_to_vpcs_alarm_configured_check(logs_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for cloudwatch_changes_to_vpcs_alarm_configured.
    
    Args:
        logs_client: Boto3 logs client (auto-created by framework)
        region (str): AWS region (auto-managed by framework)
        profile (str): AWS profile name (auto-managed by framework)
        logger: Logger instance (auto-configured by framework)
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    try:
        import boto3
        cw_client = boto3.client('cloudwatch', region_name=region)
        
        # CloudTrail log pattern for VPC changes
        vpc_pattern = '{ ($.eventName = CreateVpc) || ($.eventName = DeleteVpc) || ($.eventName = ModifyVpcAttribute) || ($.eventName = AcceptVpcPeeringConnection) || ($.eventName = CreateVpcPeeringConnection) || ($.eventName = DeleteVpcPeeringConnection) || ($.eventName = RejectVpcPeeringConnection) || ($.eventName = AttachClassicLinkVpc) || ($.eventName = DetachClassicLinkVpc) || ($.eventName = DisableVpcClassicLink) || ($.eventName = EnableVpcClassicLink) }'
        
        # Get all log groups
        paginator = logs_client.get_paginator('describe_log_groups')
        log_groups = []
        for page in paginator.paginate():
            log_groups.extend(page.get('logGroups', []))
        
        # Look for CloudTrail log groups
        cloudtrail_log_groups = []
        for log_group in log_groups:
            log_group_name = log_group.get('logGroupName', '')
            if 'cloudtrail' in log_group_name.lower() or 'trail' in log_group_name.lower():
                cloudtrail_log_groups.append(log_group_name)
        
        vpc_alarms_configured = False
        metric_filters_found = []
        alarms_found = []
        
        # Check for metric filters monitoring VPC changes
        for log_group_name in cloudtrail_log_groups:
            try:
                response = logs_client.describe_metric_filters(
                    logGroupName=log_group_name
                )
                
                for metric_filter in response.get('metricFilters', []):
                    filter_pattern = metric_filter.get('filterPattern', '')
                    
                    # Check if the metric filter monitors VPC changes
                    vpc_events = ['CreateVpc', 'DeleteVpc', 'ModifyVpcAttribute', 'VpcPeeringConnection', 'VpcClassicLink']
                    if any(event in filter_pattern for event in vpc_events):
                        metric_filters_found.append({
                            'log_group': log_group_name,
                            'filter_name': metric_filter.get('filterName'),
                            'filter_pattern': filter_pattern,
                            'metric_transformations': metric_filter.get('metricTransformations', [])
                        })
                        
                        # Check for associated alarms
                        for transformation in metric_filter.get('metricTransformations', []):
                            metric_name = transformation.get('metricName')
                            metric_namespace = transformation.get('metricNamespace')
                            
                            if metric_name and metric_namespace:
                                try:
                                    alarm_response = cw_client.describe_alarms_for_metric(
                                        MetricName=metric_name,
                                        Namespace=metric_namespace
                                    )
                                    
                                    for alarm in alarm_response.get('MetricAlarms', []):
                                        alarms_found.append({
                                            'alarm_name': alarm.get('AlarmName'),
                                            'alarm_state': alarm.get('StateValue'),
                                            'metric_name': metric_name,
                                            'metric_namespace': metric_namespace,
                                            'alarm_actions': alarm.get('AlarmActions', [])
                                        })
                                        vpc_alarms_configured = True
                                        
                                except Exception as e:
                                    logger.warning(f"Error checking alarms for metric {metric_name}: {e}")
                        
            except Exception as e:
                logger.warning(f"Error checking metric filters for log group {log_group_name}: {e}")
        
        # Create findings
        if vpc_alarms_configured and metric_filters_found:
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'CloudWatch Monitoring',
                'resource_id': f'vpc-change-monitoring-{region}',
                'status': 'COMPLIANT',
                'compliance_status': 'PASS',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                'recommendation': 'VPC change monitoring is properly configured',
                'details': {
                    'cloudtrail_log_groups': cloudtrail_log_groups,
                    'metric_filters_count': len(metric_filters_found),
                    'metric_filters': metric_filters_found,
                    'alarms_count': len(alarms_found),
                    'alarms': alarms_found
                }
            }
        else:
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'CloudWatch Monitoring',
                'resource_id': f'vpc-change-monitoring-{region}',
                'status': 'NON_COMPLIANT',
                'compliance_status': 'FAIL',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                'recommendation': COMPLIANCE_DATA.get('recommendation', 'Configure CloudWatch alarms to monitor VPC changes'),
                'details': {
                    'cloudtrail_log_groups': cloudtrail_log_groups,
                    'metric_filters_count': len(metric_filters_found),
                    'metric_filters': metric_filters_found,
                    'alarms_count': len(alarms_found),
                    'alarms': alarms_found,
                    'missing_configuration': 'VPC change monitoring alarms not properly configured'
                }
            }
        
        findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in cloudwatch_changes_to_vpcs_alarm_configured check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'CloudWatch Monitoring',
            'status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Review and remediate as needed'),
            'error': str(e)
        })
        
    return findings

def cloudwatch_changes_to_vpcs_alarm_configured(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=cloudwatch_changes_to_vpcs_alarm_configured_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = cloudwatch_changes_to_vpcs_alarm_configured(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

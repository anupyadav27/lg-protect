#!/usr/bin/env python3
"""
cis_1.5_aws - cloudwatch_log_metric_filter_disable_or_scheduled_deletion_of_kms_cmk

Ensure a log metric filter and alarm exist for disabling or scheduled deletion of customer created CMKs
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
        compliance_json_path = os.path.join(
            os.path.dirname(__file__), '..', '..', 'compliance_checks.json'
        )
        
        with open(compliance_json_path, 'r') as f:
            compliance_data = json.load(f)
        
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
        
    return {
        'compliance_name': 'cis_1.5_aws',
        'function_name': 'cloudwatch_log_metric_filter_disable_or_scheduled_deletion_of_kms_cmk',
        'id': '4.7',
        'name': 'KMS CMK Deletion Monitoring',
        'description': 'Ensure a log metric filter and alarm exist for disabling or scheduled deletion of customer created CMKs',
        'api_function': 'kms_client = boto3.client(\'kms\'), cw_client = boto3.client(\'cloudwatch\')',
        'user_function': 'list_keys(), describe_key(), list_key_policies(), describe_metric_filters(), describe_alarms()',
        'risk_level': 'HIGH',
        'recommendation': 'Configure CloudWatch log metric filter and alarm for KMS CMK deletion events'
    }

COMPLIANCE_DATA = load_compliance_metadata('cloudwatch_log_metric_filter_disable_or_scheduled_deletion_of_kms_cmk')

def cloudwatch_log_metric_filter_disable_or_scheduled_deletion_of_kms_cmk_check(logs_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for cloudwatch_log_metric_filter_disable_or_scheduled_deletion_of_kms_cmk.
    """
    findings = []
    
    try:
        import boto3
        session = boto3.Session(profile_name=profile if profile != 'default' else None)
        cw_client = session.client('cloudwatch', region_name=region)
        
        # Get all log groups
        log_groups_response = logs_client.describe_log_groups()
        log_groups = log_groups_response.get('logGroups', [])
        
        kms_deletion_filter_found = False
        kms_deletion_alarm_found = False
        
        # Check for KMS CMK deletion metric filters
        for log_group in log_groups:
            log_group_name = log_group['logGroupName']
            
            try:
                filters_response = logs_client.describe_metric_filters(
                    logGroupName=log_group_name
                )
                
                for metric_filter in filters_response.get('metricFilters', []):
                    filter_pattern = metric_filter.get('filterPattern', '').lower()
                    
                    # Check if this filter monitors KMS CMK deletion events
                    kms_deletion_indicators = [
                        'kms:disablekey',
                        'kms:schedulekeydeletion',
                        'disablekey',
                        'schedulekeydeletion',
                        'deletekey'
                    ]
                    
                    if any(indicator in filter_pattern for indicator in kms_deletion_indicators):
                        kms_deletion_filter_found = True
                        
                        # Check if there's an alarm for this metric
                        metric_transformations = metric_filter.get('metricTransformations', [])
                        for transformation in metric_transformations:
                            metric_name = transformation.get('metricName')
                            metric_namespace = transformation.get('metricNamespace')
                            
                            if metric_name and metric_namespace:
                                try:
                                    alarms_response = cw_client.describe_alarms(
                                        MetricName=metric_name,
                                        Namespace=metric_namespace
                                    )
                                    
                                    if alarms_response.get('MetricAlarms'):
                                        kms_deletion_alarm_found = True
                                        break
                                except Exception as e:
                                    logger.warning(f"Error checking alarms for metric {metric_name}: {e}")
                        
                        if kms_deletion_alarm_found:
                            break
            except Exception as e:
                logger.warning(f"Error checking metric filters for log group {log_group_name}: {e}")
        
        # Determine compliance status
        if kms_deletion_filter_found and kms_deletion_alarm_found:
            status = 'COMPLIANT'
            compliance_status = 'PASS'
            details = {
                'kms_deletion_filter_found': True,
                'kms_deletion_alarm_found': True,
                'message': 'KMS CMK deletion monitoring is properly configured'
            }
        else:
            status = 'NON_COMPLIANT'
            compliance_status = 'FAIL'
            details = {
                'kms_deletion_filter_found': kms_deletion_filter_found,
                'kms_deletion_alarm_found': kms_deletion_alarm_found,
                'message': 'KMS CMK deletion monitoring is not properly configured'
            }
        
        finding = {
            'region': region,
            'profile': profile,
            'resource_type': 'CloudWatch Log Metric Filter',
            'resource_id': f'kms-deletion-monitoring-{region}',
            'status': status,
            'compliance_status': compliance_status,
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Configure CloudWatch log metric filter and alarm for KMS CMK deletion events'),
            'details': details
        }
        
        findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in cloudwatch_log_metric_filter_disable_or_scheduled_deletion_of_kms_cmk check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'CloudWatch Log Metric Filter',
            'resource_id': f'kms-deletion-monitoring-{region}',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Configure CloudWatch log metric filter and alarm for KMS CMK deletion events'),
            'error': str(e)
        })
        
    return findings

def cloudwatch_log_metric_filter_disable_or_scheduled_deletion_of_kms_cmk(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=cloudwatch_log_metric_filter_disable_or_scheduled_deletion_of_kms_cmk_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    args = setup_command_line_interface(COMPLIANCE_DATA)
    results = cloudwatch_log_metric_filter_disable_or_scheduled_deletion_of_kms_cmk(
        profile_name=args.profile,
        region_name=args.region
    )
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

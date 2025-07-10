#!/usr/bin/env python3
"""
s3_bucket_event_notifications_enabled - Checks if S3 buckets have event notifications enabled

This compliance check verifies that S3 buckets have event notifications configured for monitoring.
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
        'compliance_name': 'aws_foundational_security_standard',
        'function_name': 's3_bucket_event_notifications_enabled',
        'id': 'S3.X',
        'name': 'S3 bucket should have event notifications enabled',
        'description': 'Checks if S3 buckets have event notifications enabled',
        'api_function': 'client = boto3.client("s3")',
        'user_function': 'get_bucket_notification_configuration()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Configure event notifications for S3 buckets to monitor access and changes'
    }

COMPLIANCE_DATA = load_compliance_metadata('s3_bucket_event_notifications_enabled')

def s3_bucket_event_notifications_enabled_check(s3_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for s3_bucket_event_notifications_enabled.
    """
    findings = []
    
    try:
        # List all S3 buckets
        response = s3_client.list_buckets()
        buckets = response.get('Buckets', [])
        
        for bucket in buckets:
            bucket_name = bucket['Name']
            
            try:
                # Check bucket notification configuration
                notification_response = s3_client.get_bucket_notification_configuration(Bucket=bucket_name)
                
                # Check for various types of notifications
                lambda_configs = notification_response.get('LambdaConfigurations', [])
                queue_configs = notification_response.get('QueueConfigurations', [])
                topic_configs = notification_response.get('TopicConfigurations', [])
                
                has_notifications = len(lambda_configs) > 0 or len(queue_configs) > 0 or len(topic_configs) > 0
                
                status = 'COMPLIANT' if has_notifications else 'NON_COMPLIANT'
                compliance_status = 'PASS' if has_notifications else 'FAIL'
                
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'S3_BUCKET',
                    'resource_id': bucket_name,
                    'status': status,
                    'compliance_status': compliance_status,
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Configure event notifications for S3 buckets to monitor access and changes'),
                    'details': {
                        'bucket_name': bucket_name,
                        'has_notifications': has_notifications,
                        'lambda_configurations_count': len(lambda_configs),
                        'queue_configurations_count': len(queue_configs),
                        'topic_configurations_count': len(topic_configs),
                        'total_configurations': len(lambda_configs) + len(queue_configs) + len(topic_configs)
                    }
                }
                
            except Exception as bucket_error:
                logger.warning(f"Could not check notifications for bucket {bucket_name}: {bucket_error}")
                # Assume no notifications if we can't check
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'S3_BUCKET',
                    'resource_id': bucket_name,
                    'status': 'NON_COMPLIANT',
                    'compliance_status': 'FAIL',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Configure event notifications for S3 buckets to monitor access and changes'),
                    'details': {
                        'bucket_name': bucket_name,
                        'has_notifications': False,
                        'reason': 'Could not check notification configuration',
                        'error': str(bucket_error)
                    }
                }
                
            findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in s3_bucket_event_notifications_enabled check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'S3_BUCKET',
            'status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Configure event notifications for S3 buckets to monitor access and changes'),
            'error': str(e)
        })
        
    return findings

def s3_bucket_event_notifications_enabled(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=s3_bucket_event_notifications_enabled_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    args = setup_command_line_interface(COMPLIANCE_DATA)
    results = s3_bucket_event_notifications_enabled(
        profile_name=args.profile,
        region_name=args.region
    )
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

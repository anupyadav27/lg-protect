#!/usr/bin/env python3
"""
iso27001_2022_aws - sqs_queues_server_side_encryption_enabled

Rules for the effective use of cryptography, including cryptographic key management, should be defined and implemented.
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
        'compliance_name': 'iso27001_2022_aws',
        'function_name': 'sqs_queues_server_side_encryption_enabled',
        'id': 'SQS.1',
        'name': 'SQS queues should have server-side encryption enabled',
        'description': 'Rules for the effective use of cryptography, including cryptographic key management, should be defined and implemented.',
        'api_function': 'client = boto3.client("sqs")',
        'user_function': 'list_queues(), get_queue_attributes()',
        'risk_level': 'HIGH',
        'recommendation': 'Enable server-side encryption for SQS queues using AWS KMS'
    }

COMPLIANCE_DATA = load_compliance_metadata('sqs_queues_server_side_encryption_enabled')

def sqs_queues_server_side_encryption_enabled_check(sqs_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for sqs_queues_server_side_encryption_enabled.
    """
    findings = []
    
    try:
        # List all SQS queues
        response = sqs_client.list_queues()
        queue_urls = response.get('QueueUrls', [])
        
        for queue_url in queue_urls:
            queue_name = queue_url.split('/')[-1]
            
            try:
                # Get queue attributes to check encryption
                attributes_response = sqs_client.get_queue_attributes(
                    QueueUrl=queue_url,
                    AttributeNames=['All']
                )
                
                attributes = attributes_response.get('Attributes', {})
                
                # Check for encryption attributes
                kms_master_key_id = attributes.get('KmsMasterKeyId')
                kms_data_key_reuse_period = attributes.get('KmsDataKeyReusePeriodSeconds')
                
                # SQS queue is encrypted if KmsMasterKeyId is present
                is_encrypted = bool(kms_master_key_id)
                
                # Additional encryption details
                encryption_details = {
                    'kms_master_key_id': kms_master_key_id,
                    'kms_data_key_reuse_period': kms_data_key_reuse_period,
                    'is_encrypted': is_encrypted
                }
                
                # Check if using AWS managed key or customer managed key
                encryption_type = 'none'
                if kms_master_key_id:
                    if kms_master_key_id == 'alias/aws/sqs':
                        encryption_type = 'aws_managed'
                    else:
                        encryption_type = 'customer_managed'
                
                status = 'COMPLIANT' if is_encrypted else 'NON_COMPLIANT'
                compliance_status = 'PASS' if is_encrypted else 'FAIL'
                
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'SQS_QUEUE',
                    'resource_id': queue_name,
                    'status': status,
                    'compliance_status': compliance_status,
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable server-side encryption for SQS queues using AWS KMS'),
                    'details': {
                        'queue_name': queue_name,
                        'queue_url': queue_url,
                        'is_encrypted': is_encrypted,
                        'encryption_type': encryption_type,
                        'kms_master_key_id': kms_master_key_id,
                        'kms_data_key_reuse_period': kms_data_key_reuse_period,
                        'visibility_timeout': attributes.get('VisibilityTimeoutSeconds'),
                        'message_retention_period': attributes.get('MessageRetentionPeriod'),
                        'delay_seconds': attributes.get('DelaySeconds'),
                        'max_receive_count': attributes.get('MaxReceiveCount')
                    }
                }
                
            except Exception as queue_error:
                logger.warning(f"Could not check encryption for queue {queue_name}: {queue_error}")
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'SQS_QUEUE',
                    'resource_id': queue_name,
                    'status': 'ERROR',
                    'compliance_status': 'ERROR',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable server-side encryption for SQS queues using AWS KMS'),
                    'details': {
                        'queue_name': queue_name,
                        'queue_url': queue_url,
                        'error': str(queue_error),
                        'reason': 'Could not retrieve queue attributes'
                    }
                }
                
            findings.append(finding)
        
        # If no queues found, add informational finding
        if not queue_urls:
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'SQS_QUEUE',
                'resource_id': 'NO_QUEUES',
                'status': 'COMPLIANT',
                'compliance_status': 'PASS',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                'recommendation': 'No SQS queues found in this region',
                'details': {
                    'message': 'No SQS queues found',
                    'queues_count': 0
                }
            }
            findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in sqs_queues_server_side_encryption_enabled check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'SQS_QUEUE',
            'status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable server-side encryption for SQS queues using AWS KMS'),
            'error': str(e)
        })
        
    return findings

def sqs_queues_server_side_encryption_enabled(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=sqs_queues_server_side_encryption_enabled_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    args = setup_command_line_interface(COMPLIANCE_DATA)
    results = sqs_queues_server_side_encryption_enabled(
        profile_name=args.profile,
        region_name=args.region
    )
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

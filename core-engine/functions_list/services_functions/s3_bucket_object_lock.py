#!/usr/bin/env python3
"""
aws_foundational_technical_review_aws - s3_bucket_object_lock

You must ensure that buckets that require public access have been reviewed to determine if public read or write access is needed and if appropriate controls are in place to control public access. When assigning access permissions, follow the principle of least privilege, an AWS best practice. For more information, refer to overview of managing access.
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
        'compliance_name': 'aws_foundational_technical_review_aws',
        'function_name': 's3_bucket_object_lock',
        'id': 'S3.17',
        'name': 'S3 bucket should have object lock enabled',
        'description': 'You must ensure that buckets that require public access have been reviewed to determine if public read or write access is needed and if appropriate controls are in place to control public access.',
        'api_function': 'client = boto3.client("s3")',
        'user_function': 'get_object_lock_configuration()',
        'risk_level': 'HIGH',
        'recommendation': 'Enable S3 Object Lock for critical buckets to prevent object deletion and modification'
    }

COMPLIANCE_DATA = load_compliance_metadata('s3_bucket_object_lock')

def s3_bucket_object_lock_check(s3_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for s3_bucket_object_lock.
    """
    findings = []
    
    try:
        # List all S3 buckets
        response = s3_client.list_buckets()
        buckets = response.get('Buckets', [])
        
        for bucket in buckets:
            bucket_name = bucket['Name']
            
            try:
                # Check object lock configuration
                lock_response = s3_client.get_object_lock_configuration(Bucket=bucket_name)
                lock_config = lock_response.get('ObjectLockConfiguration', {})
                
                object_lock_enabled = lock_config.get('ObjectLockEnabled') == 'Enabled'
                rule = lock_config.get('Rule', {})
                default_retention = rule.get('DefaultRetention', {})
                
                status = 'COMPLIANT' if object_lock_enabled else 'NON_COMPLIANT'
                compliance_status = 'PASS' if object_lock_enabled else 'FAIL'
                
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'S3_BUCKET',
                    'resource_id': bucket_name,
                    'status': status,
                    'compliance_status': compliance_status,
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable S3 Object Lock for critical buckets to prevent object deletion and modification'),
                    'details': {
                        'bucket_name': bucket_name,
                        'object_lock_enabled': object_lock_enabled,
                        'default_retention_mode': default_retention.get('Mode'),
                        'default_retention_years': default_retention.get('Years'),
                        'default_retention_days': default_retention.get('Days'),
                        'has_rule': bool(rule)
                    }
                }
                
            except s3_client.exceptions.NoSuchBucket:
                logger.warning(f"Bucket {bucket_name} not found")
                continue
            except Exception as bucket_error:
                if 'ObjectLockConfigurationNotFoundError' in str(bucket_error):
                    # No object lock configuration - non-compliant
                    finding = {
                        'region': region,
                        'profile': profile,
                        'resource_type': 'S3_BUCKET',
                        'resource_id': bucket_name,
                        'status': 'NON_COMPLIANT',
                        'compliance_status': 'FAIL',
                        'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                        'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable S3 Object Lock for critical buckets to prevent object deletion and modification'),
                        'details': {
                            'bucket_name': bucket_name,
                            'object_lock_enabled': False,
                            'reason': 'No object lock configuration found'
                        }
                    }
                else:
                    logger.warning(f"Could not check object lock for bucket {bucket_name}: {bucket_error}")
                    continue
                
            findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in s3_bucket_object_lock check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'S3_BUCKET',
            'status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable S3 Object Lock for critical buckets to prevent object deletion and modification'),
            'error': str(e)
        })
        
    return findings

def s3_bucket_object_lock(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=s3_bucket_object_lock_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    args = setup_command_line_interface(COMPLIANCE_DATA)
    results = s3_bucket_object_lock(
        profile_name=args.profile,
        region_name=args.region
    )
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

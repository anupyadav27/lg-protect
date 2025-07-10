#!/usr/bin/env python3
"""
aws_foundational_security_best_practices_aws - cloudtrail_kms_encryption_enabled

CloudTrail log files should be encrypted at rest using KMS CMKs
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
        'compliance_name': 'aws_foundational_security_best_practices_aws',
        'function_name': 'cloudtrail_kms_encryption_enabled',
        'id': 'CloudTrail.2',
        'name': 'CloudTrail should have encryption at rest enabled',
        'description': 'CloudTrail log files should be encrypted at rest using KMS CMKs',
        'api_function': 'client = boto3.client(\'cloudtrail\')',
        'user_function': 'describe_trails()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Enable KMS encryption for CloudTrail logs'
    }

COMPLIANCE_DATA = load_compliance_metadata('cloudtrail_kms_encryption_enabled')

def cloudtrail_kms_encryption_enabled_check(cloudtrail_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for cloudtrail_kms_encryption_enabled.
    """
    findings = []
    
    try:
        # Get all CloudTrail trails
        trails_response = cloudtrail_client.describe_trails()
        trails = trails_response.get('trailList', [])
        
        if not trails:
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'CloudTrail',
                'resource_id': f'no-trails-{region}',
                'status': 'COMPLIANT',
                'compliance_status': 'PASS',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable KMS encryption for CloudTrail logs'),
                'details': {
                    'message': 'No CloudTrail trails found in this region',
                    'trail_count': 0
                }
            }
            findings.append(finding)
            return findings
        
        # Check each trail for KMS encryption
        for trail in trails:
            trail_name = trail.get('Name')
            trail_arn = trail.get('TrailARN')
            s3_bucket_name = trail.get('S3BucketName')
            kms_key_id = trail.get('KMSKeyId')
            
            # Check if KMS encryption is enabled
            if kms_key_id:
                status = 'COMPLIANT'
                compliance_status = 'PASS'
                message = f'CloudTrail {trail_name} has KMS encryption enabled'
            else:
                status = 'NON_COMPLIANT'
                compliance_status = 'FAIL'
                message = f'CloudTrail {trail_name} does not have KMS encryption enabled'
            
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'CloudTrail',
                'resource_id': trail_arn or trail_name,
                'status': status,
                'compliance_status': compliance_status,
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable KMS encryption for CloudTrail logs'),
                'details': {
                    'trail_name': trail_name,
                    'trail_arn': trail_arn,
                    's3_bucket_name': s3_bucket_name,
                    'kms_key_id': kms_key_id,
                    'kms_encryption_enabled': bool(kms_key_id),
                    'is_multi_region_trail': trail.get('IsMultiRegionTrail', False),
                    'include_global_service_events': trail.get('IncludeGlobalServiceEvents', False),
                    'message': message
                }
            }
            findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in cloudtrail_kms_encryption_enabled check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'CloudTrail',
            'resource_id': f'error-{region}',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable KMS encryption for CloudTrail logs'),
            'error': str(e)
        })
        
    return findings

def cloudtrail_kms_encryption_enabled(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=cloudtrail_kms_encryption_enabled_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    args = setup_command_line_interface(COMPLIANCE_DATA)
    results = cloudtrail_kms_encryption_enabled(
        profile_name=args.profile,
        region_name=args.region
    )
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

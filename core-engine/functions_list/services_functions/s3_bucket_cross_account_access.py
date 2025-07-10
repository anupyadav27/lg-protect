#!/usr/bin/env python3
"""
s3_bucket_cross_account_access - Checks for S3 bucket cross-account access

This compliance check verifies that S3 buckets do not allow unauthorized cross-account access.
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
        'function_name': 's3_bucket_cross_account_access',
        'id': 'S3.X',
        'name': 'S3 bucket should not allow cross-account access',
        'description': 'Checks for S3 bucket cross-account access',
        'api_function': 'client = boto3.client("s3")',
        'user_function': 'get_bucket_policy()',
        'risk_level': 'HIGH',
        'recommendation': 'Review and restrict S3 bucket cross-account access'
    }

COMPLIANCE_DATA = load_compliance_metadata('s3_bucket_cross_account_access')

def s3_bucket_cross_account_access_check(s3_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for s3_bucket_cross_account_access.
    """
    findings = []
    
    try:
        # Get current account ID
        sts_client = s3_client._client_config.loader.session.create_client('sts')
        current_account = sts_client.get_caller_identity()['Account']
        
        # List all S3 buckets
        response = s3_client.list_buckets()
        buckets = response.get('Buckets', [])
        
        for bucket in buckets:
            bucket_name = bucket['Name']
            
            try:
                # Get bucket policy
                policy_response = s3_client.get_bucket_policy(Bucket=bucket_name)
                policy_doc = json.loads(policy_response['Policy'])
                
                has_cross_account_access = False
                cross_account_principals = []
                
                # Check each statement in the policy
                for statement in policy_doc.get('Statement', []):
                    principals = statement.get('Principal', {})
                    
                    # Handle different principal formats
                    if isinstance(principals, str):
                        if principals == '*':
                            has_cross_account_access = True
                            cross_account_principals.append('*')
                    elif isinstance(principals, dict):
                        aws_principals = principals.get('AWS', [])
                        if isinstance(aws_principals, str):
                            aws_principals = [aws_principals]
                        
                        for principal in aws_principals:
                            if principal == '*':
                                has_cross_account_access = True
                                cross_account_principals.append('*')
                            elif ':' in principal:
                                # Extract account ID from ARN
                                account_id = principal.split(':')[4] if len(principal.split(':')) > 4 else ''
                                if account_id and account_id != current_account:
                                    has_cross_account_access = True
                                    cross_account_principals.append(principal)
                
                status = 'NON_COMPLIANT' if has_cross_account_access else 'COMPLIANT'
                compliance_status = 'FAIL' if has_cross_account_access else 'PASS'
                
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'S3_BUCKET',
                    'resource_id': bucket_name,
                    'status': status,
                    'compliance_status': compliance_status,
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Review and restrict S3 bucket cross-account access'),
                    'details': {
                        'bucket_name': bucket_name,
                        'has_cross_account_access': has_cross_account_access,
                        'cross_account_principals': cross_account_principals,
                        'current_account': current_account
                    }
                }
                
            except s3_client.exceptions.NoSuchBucketPolicy:
                # No bucket policy - compliant
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'S3_BUCKET',
                    'resource_id': bucket_name,
                    'status': 'COMPLIANT',
                    'compliance_status': 'PASS',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Review and restrict S3 bucket cross-account access'),
                    'details': {
                        'bucket_name': bucket_name,
                        'has_cross_account_access': False,
                        'reason': 'No bucket policy configured'
                    }
                }
            except Exception as bucket_error:
                logger.warning(f"Could not check bucket policy for {bucket_name}: {bucket_error}")
                continue
                
            findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in s3_bucket_cross_account_access check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'S3_BUCKET',
            'status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Review and restrict S3 bucket cross-account access'),
            'error': str(e)
        })
        
    return findings

def s3_bucket_cross_account_access(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=s3_bucket_cross_account_access_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    args = setup_command_line_interface(COMPLIANCE_DATA)
    results = s3_bucket_cross_account_access(
        profile_name=args.profile,
        region_name=args.region
    )
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

#!/usr/bin/env python3
"""
s3_bucket_enforces_ssl - Checks if S3 buckets enforce SSL connections

This compliance check verifies that S3 buckets have policies that deny insecure HTTP requests.
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
        'function_name': 's3_bucket_enforces_ssl',
        'id': 'S3.5',
        'name': 'S3 bucket should enforce SSL connections',
        'description': 'Checks if S3 buckets enforce SSL connections',
        'api_function': 'client = boto3.client("s3")',
        'user_function': 'get_bucket_policy()',
        'risk_level': 'HIGH',
        'recommendation': 'Add bucket policy to deny insecure HTTP requests'
    }

COMPLIANCE_DATA = load_compliance_metadata('s3_bucket_enforces_ssl')

def s3_bucket_enforces_ssl_check(s3_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for s3_bucket_enforces_ssl.
    """
    findings = []
    
    try:
        # List all S3 buckets
        response = s3_client.list_buckets()
        buckets = response.get('Buckets', [])
        
        for bucket in buckets:
            bucket_name = bucket['Name']
            
            try:
                # Get bucket policy
                policy_response = s3_client.get_bucket_policy(Bucket=bucket_name)
                policy_doc = json.loads(policy_response['Policy'])
                
                enforces_ssl = False
                ssl_statements = []
                
                # Check each statement in the policy for SSL enforcement
                for statement in policy_doc.get('Statement', []):
                    effect = statement.get('Effect', '')
                    condition = statement.get('Condition', {})
                    
                    # Look for statements that deny requests without SSL
                    if effect == 'Deny':
                        # Check for aws:SecureTransport condition
                        bool_conditions = condition.get('Bool', {})
                        if 'aws:SecureTransport' in bool_conditions:
                            secure_transport = bool_conditions['aws:SecureTransport']
                            if secure_transport == 'false' or secure_transport is False:
                                enforces_ssl = True
                                ssl_statements.append(statement)
                        
                        # Check for StringEquals condition with s3:x-amz-server-side-encryption
                        string_conditions = condition.get('StringEquals', {})
                        if 's3:x-amz-server-side-encryption' in string_conditions:
                            # This also indicates SSL enforcement in some contexts
                            ssl_statements.append(statement)
                
                status = 'COMPLIANT' if enforces_ssl else 'NON_COMPLIANT'
                compliance_status = 'PASS' if enforces_ssl else 'FAIL'
                
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'S3_BUCKET',
                    'resource_id': bucket_name,
                    'status': status,
                    'compliance_status': compliance_status,
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Add bucket policy to deny insecure HTTP requests'),
                    'details': {
                        'bucket_name': bucket_name,
                        'enforces_ssl': enforces_ssl,
                        'ssl_statements_count': len(ssl_statements),
                        'has_bucket_policy': True
                    }
                }
                
            except s3_client.exceptions.NoSuchBucketPolicy:
                # No bucket policy - non-compliant
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'S3_BUCKET',
                    'resource_id': bucket_name,
                    'status': 'NON_COMPLIANT',
                    'compliance_status': 'FAIL',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Add bucket policy to deny insecure HTTP requests'),
                    'details': {
                        'bucket_name': bucket_name,
                        'enforces_ssl': False,
                        'has_bucket_policy': False,
                        'reason': 'No bucket policy configured'
                    }
                }
            except Exception as bucket_error:
                logger.warning(f"Could not check bucket policy for {bucket_name}: {bucket_error}")
                continue
                
            findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in s3_bucket_enforces_ssl check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'S3_BUCKET',
            'status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Add bucket policy to deny insecure HTTP requests'),
            'error': str(e)
        })
        
    return findings

def s3_bucket_enforces_ssl(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=s3_bucket_enforces_ssl_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    args = setup_command_line_interface(COMPLIANCE_DATA)
    results = s3_bucket_enforces_ssl(
        profile_name=args.profile,
        region_name=args.region
    )
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

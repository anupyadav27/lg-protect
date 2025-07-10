#!/usr/bin/env python3
"""
s3_bucket_default_encryption - Checks if S3 buckets have default encryption enabled

This compliance check verifies that S3 buckets have default server-side encryption configured.
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
        'function_name': 's3_bucket_default_encryption',
        'id': 'S3.4',
        'name': 'S3 bucket should have default encryption enabled',
        'description': 'Checks if S3 buckets have default encryption enabled',
        'api_function': 'client = boto3.client("s3")',
        'user_function': 'get_bucket_encryption()',
        'risk_level': 'HIGH',
        'recommendation': 'Enable default encryption for S3 buckets'
    }

COMPLIANCE_DATA = load_compliance_metadata('s3_bucket_default_encryption')

def s3_bucket_default_encryption_check(s3_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for s3_bucket_default_encryption.
    """
    findings = []
    
    try:
        # List all S3 buckets
        response = s3_client.list_buckets()
        buckets = response.get('Buckets', [])
        
        for bucket in buckets:
            bucket_name = bucket['Name']
            
            try:
                # Check bucket encryption configuration
                encryption_response = s3_client.get_bucket_encryption(Bucket=bucket_name)
                encryption_config = encryption_response.get('ServerSideEncryptionConfiguration', {})
                rules = encryption_config.get('Rules', [])
                
                has_default_encryption = False
                encryption_algorithms = []
                
                for rule in rules:
                    default_encryption = rule.get('ApplyServerSideEncryptionByDefault', {})
                    algorithm = default_encryption.get('SSEAlgorithm')
                    if algorithm:
                        has_default_encryption = True
                        encryption_algorithms.append(algorithm)
                
                status = 'COMPLIANT' if has_default_encryption else 'NON_COMPLIANT'
                compliance_status = 'PASS' if has_default_encryption else 'FAIL'
                
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'S3_BUCKET',
                    'resource_id': bucket_name,
                    'status': status,
                    'compliance_status': compliance_status,
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable default encryption for S3 buckets'),
                    'details': {
                        'bucket_name': bucket_name,
                        'has_default_encryption': has_default_encryption,
                        'encryption_algorithms': encryption_algorithms,
                        'encryption_rules_count': len(rules)
                    }
                }
                
            except s3_client.exceptions.NoSuchBucket:
                logger.warning(f"Bucket {bucket_name} not found")
                continue
            except Exception as bucket_error:
                if 'ServerSideEncryptionConfigurationNotFoundError' in str(bucket_error) or 'NoSuchKey' in str(bucket_error):
                    # No encryption configuration - non-compliant
                    finding = {
                        'region': region,
                        'profile': profile,
                        'resource_type': 'S3_BUCKET',
                        'resource_id': bucket_name,
                        'status': 'NON_COMPLIANT',
                        'compliance_status': 'FAIL',
                        'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                        'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable default encryption for S3 buckets'),
                        'details': {
                            'bucket_name': bucket_name,
                            'has_default_encryption': False,
                            'reason': 'No encryption configuration found'
                        }
                    }
                else:
                    logger.warning(f"Could not check encryption for bucket {bucket_name}: {bucket_error}")
                    continue
                
            findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in s3_bucket_default_encryption check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'S3_BUCKET',
            'status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable default encryption for S3 buckets'),
            'error': str(e)
        })
        
    return findings

def s3_bucket_default_encryption(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=s3_bucket_default_encryption_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    args = setup_command_line_interface(COMPLIANCE_DATA)
    results = s3_bucket_default_encryption(
        profile_name=args.profile,
        region_name=args.region
    )
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

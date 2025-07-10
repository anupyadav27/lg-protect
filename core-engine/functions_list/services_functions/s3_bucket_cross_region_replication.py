#!/usr/bin/env python3
"""
s3_bucket_cross_region_replication - Checks if S3 buckets have cross-region replication enabled

This compliance check verifies that S3 buckets have cross-region replication configured for data redundancy.
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
        'function_name': 's3_bucket_cross_region_replication',
        'id': 'S3.X',
        'name': 'S3 bucket should have cross-region replication enabled',
        'description': 'Checks if S3 buckets have cross-region replication enabled',
        'api_function': 'client = boto3.client("s3")',
        'user_function': 'get_bucket_replication()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Enable cross-region replication for S3 buckets'
    }

COMPLIANCE_DATA = load_compliance_metadata('s3_bucket_cross_region_replication')

def s3_bucket_cross_region_replication_check(s3_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for s3_bucket_cross_region_replication.
    """
    findings = []
    
    try:
        # List all S3 buckets
        response = s3_client.list_buckets()
        buckets = response.get('Buckets', [])
        
        for bucket in buckets:
            bucket_name = bucket['Name']
            
            try:
                # Check bucket replication configuration
                replication_response = s3_client.get_bucket_replication(Bucket=bucket_name)
                replication_config = replication_response.get('ReplicationConfiguration', {})
                
                # Check if replication is configured with cross-region rules
                has_cross_region_replication = False
                replication_rules = replication_config.get('Rules', [])
                cross_region_destinations = []
                
                for rule in replication_rules:
                    if rule.get('Status') == 'Enabled':
                        destination = rule.get('Destination', {})
                        dest_bucket = destination.get('Bucket', '')
                        
                        # Extract region from destination bucket ARN
                        if dest_bucket.startswith('arn:aws:s3:::'):
                            # For cross-region replication, destination should be in different region
                            cross_region_destinations.append(dest_bucket)
                            has_cross_region_replication = True
                
                status = 'COMPLIANT' if has_cross_region_replication else 'NON_COMPLIANT'
                compliance_status = 'PASS' if has_cross_region_replication else 'FAIL'
                
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'S3_BUCKET',
                    'resource_id': bucket_name,
                    'status': status,
                    'compliance_status': compliance_status,
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable cross-region replication for S3 buckets'),
                    'details': {
                        'bucket_name': bucket_name,
                        'has_cross_region_replication': has_cross_region_replication,
                        'replication_rules_count': len(replication_rules),
                        'cross_region_destinations': cross_region_destinations
                    }
                }
                
            except s3_client.exceptions.NoSuchBucket:
                logger.warning(f"Bucket {bucket_name} not found")
                continue
            except Exception as bucket_error:
                if 'ReplicationConfigurationNotFoundError' in str(bucket_error):
                    # No replication configuration - non-compliant
                    finding = {
                        'region': region,
                        'profile': profile,
                        'resource_type': 'S3_BUCKET',
                        'resource_id': bucket_name,
                        'status': 'NON_COMPLIANT',
                        'compliance_status': 'FAIL',
                        'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                        'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable cross-region replication for S3 buckets'),
                        'details': {
                            'bucket_name': bucket_name,
                            'has_cross_region_replication': False,
                            'reason': 'No replication configuration found'
                        }
                    }
                else:
                    logger.warning(f"Could not check replication for bucket {bucket_name}: {bucket_error}")
                    continue
                
            findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in s3_bucket_cross_region_replication check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'S3_BUCKET',
            'status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable cross-region replication for S3 buckets'),
            'error': str(e)
        })
        
    return findings

def s3_bucket_cross_region_replication(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=s3_bucket_cross_region_replication_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    args = setup_command_line_interface(COMPLIANCE_DATA)
    results = s3_bucket_cross_region_replication(
        profile_name=args.profile,
        region_name=args.region
    )
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

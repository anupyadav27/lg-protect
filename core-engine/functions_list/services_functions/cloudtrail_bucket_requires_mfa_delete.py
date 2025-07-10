#!/usr/bin/env python3
"""
iso27001_2022_aws - cloudtrail_bucket_requires_mfa_delete

Backup copies of information, software and systems should be maintained and regularly tested in accordance with the agreed topic-specific policy on backup.
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
                    'recommendation': entry.get('Recommendation', 'Enable MFA delete on CloudTrail S3 buckets')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'iso27001_2022_aws',
        'function_name': 'cloudtrail_bucket_requires_mfa_delete',
        'id': 'ISO27001-2022-AWS-CT-MFA',
        'name': 'CloudTrail S3 Bucket MFA Delete',
        'description': 'Backup copies of information, software and systems should be maintained and regularly tested in accordance with the agreed topic-specific policy on backup.',
        'api_function': 'client = boto3.client(\'cloudtrail\'), client = boto3.client(\'s3\')',
        'user_function': 'describe_trails(), get_bucket_versioning()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Enable MFA delete on CloudTrail S3 buckets'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('cloudtrail_bucket_requires_mfa_delete')

def cloudtrail_bucket_requires_mfa_delete_check(cloudtrail_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Check if CloudTrail S3 buckets have MFA delete enabled.
    
    Args:
        cloudtrail_client: Boto3 CloudTrail client
        region (str): AWS region
        profile (str): AWS profile name
        logger: Logger instance
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    try:
        # Get all CloudTrail trails
        response = cloudtrail_client.describe_trails()
        trails = response.get('trailList', [])
        
        if not trails:
            findings.append({
                'region': region,
                'profile': profile,
                'resource_type': 'CloudTrail',
                'resource_id': f'no-trails-{region}',
                'status': 'COMPLIANT',
                'compliance_status': 'PASS',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                'recommendation': 'No CloudTrail trails found in this region',
                'details': {
                    'trail_count': 0,
                    'reason': 'No trails to evaluate'
                }
            })
            return findings
        
        # Create S3 client to check bucket versioning
        import boto3
        session = cloudtrail_client.meta.client._client_config.region_name
        s3_client = boto3.client('s3', region_name=region)
        
        for trail in trails:
            trail_name = trail.get('Name', 'Unknown')
            trail_arn = trail.get('TrailARN', '')
            s3_bucket_name = trail.get('S3BucketName')
            
            if not s3_bucket_name:
                findings.append({
                    'region': region,
                    'profile': profile,
                    'resource_type': 'CloudTrail',
                    'resource_id': trail_name,
                    'status': 'NON_COMPLIANT',
                    'compliance_status': 'FAIL',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable MFA delete on CloudTrail S3 buckets'),
                    'details': {
                        'trail_name': trail_name,
                        'trail_arn': trail_arn,
                        'issue': 'No S3 bucket configured for trail'
                    }
                })
                continue
            
            try:
                # Check bucket versioning and MFA delete status
                versioning_response = s3_client.get_bucket_versioning(Bucket=s3_bucket_name)
                
                versioning_status = versioning_response.get('Status', 'Disabled')
                mfa_delete = versioning_response.get('MfaDelete', 'Disabled')
                
                if mfa_delete == 'Enabled':
                    # MFA delete is enabled - compliant
                    findings.append({
                        'region': region,
                        'profile': profile,
                        'resource_type': 'CloudTrail',
                        'resource_id': trail_name,
                        'status': 'COMPLIANT',
                        'compliance_status': 'PASS',
                        'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                        'recommendation': 'CloudTrail S3 bucket has MFA delete enabled',
                        'details': {
                            'trail_name': trail_name,
                            'trail_arn': trail_arn,
                            's3_bucket_name': s3_bucket_name,
                            'versioning_status': versioning_status,
                            'mfa_delete_status': mfa_delete
                        }
                    })
                else:
                    # MFA delete is not enabled - non-compliant
                    findings.append({
                        'region': region,
                        'profile': profile,
                        'resource_type': 'CloudTrail',
                        'resource_id': trail_name,
                        'status': 'NON_COMPLIANT',
                        'compliance_status': 'FAIL',
                        'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                        'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable MFA delete on CloudTrail S3 buckets'),
                        'details': {
                            'trail_name': trail_name,
                            'trail_arn': trail_arn,
                            's3_bucket_name': s3_bucket_name,
                            'versioning_status': versioning_status,
                            'mfa_delete_status': mfa_delete,
                            'issue': 'MFA delete is not enabled on CloudTrail S3 bucket'
                        }
                    })
                    
            except Exception as e:
                logger.warning(f"Error checking S3 bucket {s3_bucket_name} for trail {trail_name}: {e}")
                findings.append({
                    'region': region,
                    'profile': profile,
                    'resource_type': 'CloudTrail',
                    'resource_id': trail_name,
                    'status': 'ERROR',
                    'compliance_status': 'ERROR',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable MFA delete on CloudTrail S3 buckets'),
                    'details': {
                        'trail_name': trail_name,
                        'trail_arn': trail_arn,
                        's3_bucket_name': s3_bucket_name,
                        'error': str(e)
                    }
                })
        
    except Exception as e:
        logger.error(f"Error in cloudtrail_bucket_requires_mfa_delete check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'CloudTrail',
            'resource_id': f'cloudtrail-mfa-check-{region}',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable MFA delete on CloudTrail S3 buckets'),
            'error': str(e)
        })
        
    return findings

def cloudtrail_bucket_requires_mfa_delete(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=cloudtrail_bucket_requires_mfa_delete_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = cloudtrail_bucket_requires_mfa_delete(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

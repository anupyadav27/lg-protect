#!/usr/bin/env python3
"""
cis_1.5_aws - cloudtrail_logs_s3_bucket_access_logging_enabled

Ensure CloudTrail logs S3 bucket access logging is enabled
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
                    'recommendation': entry.get('Recommendation', 'Review and remediate as needed')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'cis_1.5_aws',
        'function_name': 'cloudtrail_logs_s3_bucket_access_logging_enabled',
        'id': '3.6',
        'name': 'CloudTrail S3 Bucket Access Logging',
        'description': 'Ensure CloudTrail logs S3 bucket access logging is enabled',
        'api_function': 'cloudtrail_client = boto3.client(\'cloudtrail\'); s3_client = boto3.client(\'s3\')',
        'user_function': 'cloudtrail.describe_trails(), s3.get_bucket_logging(Bucket=bucket-name)',
        'risk_level': 'MEDIUM',
        'recommendation': 'Enable S3 access logging for CloudTrail buckets to track bucket access patterns'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('cloudtrail_logs_s3_bucket_access_logging_enabled')

def cloudtrail_logs_s3_bucket_access_logging_enabled_check(cloudtrail_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for cloudtrail_logs_s3_bucket_access_logging_enabled.
    
    Args:
        cloudtrail_client: Boto3 CloudTrail client (auto-created by framework)
        region (str): AWS region (auto-managed by framework)
        profile (str): AWS profile name (auto-managed by framework)
        logger: Logger instance (auto-configured by framework)
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    try:
        # Import boto3 for S3 client
        import boto3
        
        # Create S3 client
        s3_client = boto3.client('s3')
        
        # Get all CloudTrail trails
        response = cloudtrail_client.describe_trails()
        trails = response.get('trailList', [])
        
        if not trails:
            findings.append({
                'region': region,
                'profile': profile,
                'resource_type': 'CloudTrail',
                'resource_id': 'no-trails',
                'status': 'NON_COMPLIANT',
                'compliance_status': 'FAIL',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                'recommendation': COMPLIANCE_DATA.get('recommendation', 'Create CloudTrail trails with S3 access logging'),
                'details': {
                    'issue': 'No CloudTrail trails found',
                    'trails_count': 0
                }
            })
            return findings
        
        checked_buckets = set()  # To avoid checking the same bucket multiple times
        
        for trail in trails:
            trail_name = trail.get('Name', 'unknown')
            trail_arn = trail.get('TrailARN', 'unknown')
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
                    'recommendation': 'Configure S3 bucket for CloudTrail trail',
                    'details': {
                        'trail_name': trail_name,
                        'trail_arn': trail_arn,
                        'issue': 'No S3 bucket configured for trail'
                    }
                })
                continue
            
            # Skip if we've already checked this bucket
            if s3_bucket_name in checked_buckets:
                continue
            
            checked_buckets.add(s3_bucket_name)
            
            bucket_logging_details = {
                'bucket_name': s3_bucket_name,
                'trail_name': trail_name,
                'trail_arn': trail_arn,
                'access_logging_enabled': False,
                'logging_configuration': None
            }
            
            try:
                # Check bucket access logging configuration
                logging_response = s3_client.get_bucket_logging(Bucket=s3_bucket_name)
                logging_config = logging_response.get('LoggingEnabled', {})
                
                if logging_config:
                    target_bucket = logging_config.get('TargetBucket')
                    target_prefix = logging_config.get('TargetPrefix', '')
                    target_grants = logging_config.get('TargetGrants', [])
                    
                    bucket_logging_details.update({
                        'access_logging_enabled': True,
                        'logging_configuration': {
                            'target_bucket': target_bucket,
                            'target_prefix': target_prefix,
                            'target_grants_count': len(target_grants)
                        }
                    })
                    
                    # Create compliant finding
                    findings.append({
                        'region': region,
                        'profile': profile,
                        'resource_type': 'S3 Bucket (CloudTrail)',
                        'resource_id': s3_bucket_name,
                        'status': 'COMPLIANT',
                        'compliance_status': 'PASS',
                        'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                        'recommendation': 'S3 access logging is properly configured for CloudTrail bucket',
                        'details': bucket_logging_details
                    })
                else:
                    # No logging configuration found
                    bucket_logging_details['access_logging_enabled'] = False
                    bucket_logging_details['issue'] = 'No access logging configuration found'
                    
                    findings.append({
                        'region': region,
                        'profile': profile,
                        'resource_type': 'S3 Bucket (CloudTrail)',
                        'resource_id': s3_bucket_name,
                        'status': 'NON_COMPLIANT',
                        'compliance_status': 'FAIL',
                        'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                        'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable S3 access logging for CloudTrail bucket'),
                        'details': bucket_logging_details
                    })
                    
            except Exception as e:
                logger.error(f"Error checking access logging for bucket {s3_bucket_name}: {e}")
                bucket_logging_details['error'] = str(e)
                
                findings.append({
                    'region': region,
                    'profile': profile,
                    'resource_type': 'S3 Bucket (CloudTrail)',
                    'resource_id': s3_bucket_name,
                    'status': 'ERROR',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                    'recommendation': 'Review bucket access logging configuration',
                    'details': bucket_logging_details
                })
        
    except Exception as e:
        logger.error(f"Error in cloudtrail_logs_s3_bucket_access_logging_enabled check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'CloudTrail S3 Buckets',
            'resource_id': f's3-access-logging-{region}',
            'status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Review and remediate as needed'),
            'error': str(e)
        })
        
    return findings

def cloudtrail_logs_s3_bucket_access_logging_enabled(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=cloudtrail_logs_s3_bucket_access_logging_enabled_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = cloudtrail_logs_s3_bucket_access_logging_enabled(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

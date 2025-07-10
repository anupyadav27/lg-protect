#!/usr/bin/env python3
"""
cis_1.5_aws - cloudtrail_logs_s3_bucket_is_not_publicly_accessible

Ensure CloudTrail trails are integrated with CloudWatch Logs
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
        'function_name': 'cloudtrail_logs_s3_bucket_is_not_publicly_accessible',
        'id': '3.4',
        'name': 'CloudTrail S3 Bucket Public Access',
        'description': 'Ensure CloudTrail S3 bucket is not publicly accessible',
        'api_function': 'cloudtrail = boto3.client(\'cloudtrail\'); s3 = boto3.client(\'s3\')',
        'user_function': 'cloudtrail.describe_trails(), s3.get_bucket_policy_status(Bucket=...)',
        'risk_level': 'HIGH',
        'recommendation': 'Ensure CloudTrail S3 buckets are not publicly accessible to prevent unauthorized access to audit logs'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('cloudtrail_logs_s3_bucket_is_not_publicly_accessible')

def cloudtrail_logs_s3_bucket_is_not_publicly_accessible_check(cloudtrail_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for cloudtrail_logs_s3_bucket_is_not_publicly_accessible.
    
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
        
        # Create S3 client using the same session as CloudTrail
        s3_client = cloudtrail_client._client_config.region_name
        s3_client = boto3.client('s3', region_name=s3_client)
        
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
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                'recommendation': COMPLIANCE_DATA.get('recommendation', 'Create CloudTrail trails with secure S3 buckets'),
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
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
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
            
            bucket_public_access_details = {
                'bucket_name': s3_bucket_name,
                'trail_name': trail_name,
                'trail_arn': trail_arn,
                'public_access_checks': {}
            }
            
            is_bucket_public = False
            public_access_reasons = []
            
            try:
                # Check bucket policy status
                try:
                    policy_status_response = s3_client.get_bucket_policy_status(Bucket=s3_bucket_name)
                    policy_status = policy_status_response.get('PolicyStatus', {})
                    is_public_policy = policy_status.get('IsPublic', False)
                    
                    bucket_public_access_details['public_access_checks']['bucket_policy_public'] = is_public_policy
                    
                    if is_public_policy:
                        is_bucket_public = True
                        public_access_reasons.append('Bucket policy allows public access')
                        
                except s3_client.exceptions.NoSuchBucketPolicy:
                    bucket_public_access_details['public_access_checks']['bucket_policy_public'] = False
                except Exception as e:
                    logger.warning(f"Could not check bucket policy status for {s3_bucket_name}: {e}")
                    bucket_public_access_details['public_access_checks']['bucket_policy_error'] = str(e)
                
                # Check public access block configuration
                try:
                    public_access_block_response = s3_client.get_public_access_block(Bucket=s3_bucket_name)
                    public_access_config = public_access_block_response.get('PublicAccessBlockConfiguration', {})
                    
                    block_public_acls = public_access_config.get('BlockPublicAcls', False)
                    ignore_public_acls = public_access_config.get('IgnorePublicAcls', False)
                    block_public_policy = public_access_config.get('BlockPublicPolicy', False)
                    restrict_public_buckets = public_access_config.get('RestrictPublicBuckets', False)
                    
                    bucket_public_access_details['public_access_checks'].update({
                        'block_public_acls': block_public_acls,
                        'ignore_public_acls': ignore_public_acls,
                        'block_public_policy': block_public_policy,
                        'restrict_public_buckets': restrict_public_buckets
                    })
                    
                    # If any of these are False, the bucket could be public
                    if not all([block_public_acls, ignore_public_acls, block_public_policy, restrict_public_buckets]):
                        is_bucket_public = True
                        if not block_public_acls:
                            public_access_reasons.append('Public ACLs are not blocked')
                        if not ignore_public_acls:
                            public_access_reasons.append('Public ACLs are not ignored')
                        if not block_public_policy:
                            public_access_reasons.append('Public bucket policies are not blocked')
                        if not restrict_public_buckets:
                            public_access_reasons.append('Public bucket access is not restricted')
                            
                except s3_client.exceptions.NoSuchPublicAccessBlockConfiguration:
                    is_bucket_public = True
                    public_access_reasons.append('No public access block configuration found')
                    bucket_public_access_details['public_access_checks']['public_access_block_missing'] = True
                except Exception as e:
                    logger.warning(f"Could not check public access block for {s3_bucket_name}: {e}")
                    bucket_public_access_details['public_access_checks']['public_access_block_error'] = str(e)
                
                # Check bucket ACL
                try:
                    acl_response = s3_client.get_bucket_acl(Bucket=s3_bucket_name)
                    grants = acl_response.get('Grants', [])
                    
                    public_acl_found = False
                    for grant in grants:
                        grantee = grant.get('Grantee', {})
                        grantee_uri = grantee.get('URI', '')
                        
                        # Check for public read or write permissions
                        if ('AllUsers' in grantee_uri or 
                            'AuthenticatedUsers' in grantee_uri or
                            'http://acs.amazonaws.com/groups/global/AllUsers' in grantee_uri or
                            'http://acs.amazonaws.com/groups/global/AuthenticatedUsers' in grantee_uri):
                            public_acl_found = True
                            permission = grant.get('Permission', 'UNKNOWN')
                            public_access_reasons.append(f'Public ACL grant found: {permission}')
                    
                    bucket_public_access_details['public_access_checks']['public_acl_found'] = public_acl_found
                    
                    if public_acl_found:
                        is_bucket_public = True
                        
                except Exception as e:
                    logger.warning(f"Could not check bucket ACL for {s3_bucket_name}: {e}")
                    bucket_public_access_details['public_access_checks']['bucket_acl_error'] = str(e)
                
            except Exception as e:
                logger.error(f"Error checking public access for bucket {s3_bucket_name}: {e}")
                bucket_public_access_details['error'] = str(e)
            
            bucket_public_access_details['is_public'] = is_bucket_public
            bucket_public_access_details['public_access_reasons'] = public_access_reasons
            
            # Create finding for this bucket
            if is_bucket_public:
                findings.append({
                    'region': region,
                    'profile': profile,
                    'resource_type': 'S3 Bucket (CloudTrail)',
                    'resource_id': s3_bucket_name,
                    'status': 'NON_COMPLIANT',
                    'compliance_status': 'FAIL',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Configure bucket to block public access'),
                    'details': bucket_public_access_details
                })
            else:
                findings.append({
                    'region': region,
                    'profile': profile,
                    'resource_type': 'S3 Bucket (CloudTrail)',
                    'resource_id': s3_bucket_name,
                    'status': 'COMPLIANT',
                    'compliance_status': 'PASS',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                    'recommendation': 'CloudTrail S3 bucket is properly secured against public access',
                    'details': bucket_public_access_details
                })
        
    except Exception as e:
        logger.error(f"Error in cloudtrail_logs_s3_bucket_is_not_publicly_accessible check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'CloudTrail S3 Buckets',
            'resource_id': f's3-public-access-{region}',
            'status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Review and remediate as needed'),
            'error': str(e)
        })
        
    return findings

def cloudtrail_logs_s3_bucket_is_not_publicly_accessible(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=cloudtrail_logs_s3_bucket_is_not_publicly_accessible_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = cloudtrail_logs_s3_bucket_is_not_publicly_accessible(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

#!/usr/bin/env python3
"""
aws_foundational_security_best_practices_aws - s3_bucket_public_access

This control checks whether the following public access block settings are configured from account level
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
                    'recommendation': entry.get('Recommendation', 'Block public access to S3 buckets')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'aws_foundational_security_best_practices_aws',
        'function_name': 's3_bucket_public_access',
        'id': 'S3.1',
        'name': 'S3 general purpose buckets should block public access',
        'description': 'This control checks whether the following public access block settings are configured from account level',
        'api_function': 'client = boto3.client(\'s3\')',
        'user_function': 'list_buckets(), get_bucket_acl(), get_bucket_policy()',
        'risk_level': 'HIGH',
        'recommendation': 'Block public access to S3 buckets to prevent unauthorized data exposure'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('s3_bucket_public_access')

def s3_bucket_public_access_check(s3_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for s3_bucket_public_access.
    
    Args:
        s3_client: Boto3 S3 client (auto-created by framework)
        region (str): AWS region (auto-managed by framework)
        profile (str): AWS profile name (auto-managed by framework)
        logger: Logger instance (auto-configured by framework)
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    try:
        # Get all S3 buckets
        response = s3_client.list_buckets()
        buckets = response.get('Buckets', [])
        
        if not buckets:
            # No S3 buckets found, create an informational finding
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'S3 Bucket',
                'resource_id': f'no-buckets-{region}',
                'status': 'COMPLIANT',
                'compliance_status': 'PASS',
                'risk_level': 'LOW',
                'recommendation': 'No S3 buckets found in this account',
                'details': {
                    'buckets_count': 0,
                    'message': 'No S3 buckets found to check for public access'
                }
            }
            findings.append(finding)
            return findings
        
        for bucket in buckets:
            bucket_name = bucket.get('Name', 'unknown')
            creation_date = bucket.get('CreationDate', 'unknown')
            
            is_public = False
            public_access_details = {}
            
            try:
                # Check bucket public access block configuration
                try:
                    pab_response = s3_client.get_public_access_block(Bucket=bucket_name)
                    pab_config = pab_response.get('PublicAccessBlockConfiguration', {})
                    
                    block_public_acls = pab_config.get('BlockPublicAcls', False)
                    ignore_public_acls = pab_config.get('IgnorePublicAcls', False)
                    block_public_policy = pab_config.get('BlockPublicPolicy', False)
                    restrict_public_buckets = pab_config.get('RestrictPublicBuckets', False)
                    
                    public_access_details['public_access_block'] = {
                        'block_public_acls': block_public_acls,
                        'ignore_public_acls': ignore_public_acls,
                        'block_public_policy': block_public_policy,
                        'restrict_public_buckets': restrict_public_buckets
                    }
                    
                    # If all four settings are not enabled, consider it potentially public
                    if not all([block_public_acls, ignore_public_acls, block_public_policy, restrict_public_buckets]):
                        is_public = True
                        
                except Exception as pab_error:
                    # No public access block configuration means potentially public
                    logger.warning(f"Could not get public access block for bucket {bucket_name}: {pab_error}")
                    is_public = True
                    public_access_details['public_access_block'] = 'Not configured'
                
                # Check bucket ACL for public access
                try:
                    acl_response = s3_client.get_bucket_acl(Bucket=bucket_name)
                    grants = acl_response.get('Grants', [])
                    
                    public_acl_grants = []
                    for grant in grants:
                        grantee = grant.get('Grantee', {})
                        grantee_type = grantee.get('Type', '')
                        grantee_uri = grantee.get('URI', '')
                        permission = grant.get('Permission', '')
                        
                        # Check for public ACL grants
                        if (grantee_type == 'Group' and 
                            ('AllUsers' in grantee_uri or 'AuthenticatedUsers' in grantee_uri)):
                            is_public = True
                            public_acl_grants.append({
                                'grantee_uri': grantee_uri,
                                'permission': permission
                            })
                    
                    public_access_details['public_acl_grants'] = public_acl_grants
                    
                except Exception as acl_error:
                    logger.warning(f"Could not get ACL for bucket {bucket_name}: {acl_error}")
                    public_access_details['acl_error'] = str(acl_error)
                
                # Check bucket policy for public statements
                try:
                    policy_response = s3_client.get_bucket_policy(Bucket=bucket_name)
                    policy_document = policy_response.get('Policy', '{}')
                    
                    if policy_document:
                        policy = json.loads(policy_document)
                        statements = policy.get('Statement', [])
                        
                        public_policy_statements = []
                        for statement in statements:
                            principal = statement.get('Principal', {})
                            effect = statement.get('Effect', '')
                            
                            # Check for public policy statements
                            if (effect == 'Allow' and 
                                (principal == '*' or 
                                 (isinstance(principal, dict) and principal.get('AWS') == '*'))):
                                is_public = True
                                public_policy_statements.append(statement)
                        
                        public_access_details['public_policy_statements'] = public_policy_statements
                    
                except Exception as policy_error:
                    # No bucket policy or access denied is fine
                    if 'NoSuchBucketPolicy' not in str(policy_error):
                        logger.warning(f"Could not get policy for bucket {bucket_name}: {policy_error}")
                
            except Exception as bucket_error:
                logger.warning(f"Error checking bucket {bucket_name}: {bucket_error}")
                public_access_details['bucket_error'] = str(bucket_error)
            
            # Determine compliance status
            if not is_public:
                status = 'COMPLIANT'
                compliance_status = 'PASS'
                risk_level = 'LOW'
                recommendation = 'S3 bucket is properly configured to block public access'
            else:
                status = 'NON_COMPLIANT'
                compliance_status = 'FAIL'
                risk_level = COMPLIANCE_DATA.get('risk_level', 'HIGH')
                recommendation = COMPLIANCE_DATA.get('recommendation', 'Configure bucket to block public access')
            
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'S3 Bucket',
                'resource_id': bucket_name,
                'status': status,
                'compliance_status': compliance_status,
                'risk_level': risk_level,
                'recommendation': recommendation,
                'details': {
                    'bucket_name': bucket_name,
                    'creation_date': str(creation_date),
                    'is_public': is_public,
                    'is_compliant': not is_public,
                    'public_access_details': public_access_details,
                    'security_note': 'Public S3 buckets can expose sensitive data to unauthorized users'
                }
            }
            
            findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in s3_bucket_public_access check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'S3 Bucket',
            'resource_id': f'error-check-{region}',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Block public access to S3 buckets'),
            'error': str(e)
        })
        
    return findings

def s3_bucket_public_access(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=s3_bucket_public_access_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = s3_bucket_public_access(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

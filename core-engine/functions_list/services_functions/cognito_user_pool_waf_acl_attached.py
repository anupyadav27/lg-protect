#!/usr/bin/env python3
"""
soc2_aws - cognito_user_pool_waf_acl_attached

Implements Boundary Protection Systems — Boundary protection systems (for example, firewalls, demilitarized zones, and intrusion detection systems) are implemented to protect external access points from attempts and unauthorized access and are monitored to detect such attempts.
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
                    'recommendation': entry.get('Recommendation', 'Attach WAF ACL to Cognito User Pool for boundary protection')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'soc2_aws',
        'function_name': 'cognito_user_pool_waf_acl_attached',
        'id': 'cc_6_6',
        'name': 'CC6.6 The entity implements logical access security measures to protect against threats from sources outside its system boundaries',
        'description': 'Implements Boundary Protection Systems — Boundary protection systems (for example, firewalls, demilitarized zones, and intrusion detection systems) are implemented to protect external access points from attempts and unauthorized access and are monitored to detect such attempts.',
        'api_function': 'client1=boto3.client(\'cognito-idp\'), client2=boto3.client(\'wafv2\')',
        'user_function': 'list_user_pools(), get_web_acl_for_resource()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Attach WAF ACL to Cognito User Pool for boundary protection'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('cognito_user_pool_waf_acl_attached')

def cognito_user_pool_waf_acl_attached_check(cognito_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for cognito_user_pool_waf_acl_attached.
    
    Args:
        cognito_client: Boto3 Cognito IDP client (auto-created by framework)
        region (str): AWS region (auto-managed by framework)
        profile (str): AWS profile name (auto-managed by framework)
        logger: Logger instance (auto-configured by framework)
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    try:
        # Import boto3 to create additional clients
        import boto3
        
        # Create WAFv2 client for checking WAF associations
        session = cognito_client._client_config.__dict__.get('_user_provided_options', {}).get('region_name', region)
        wafv2_client = boto3.client('wafv2', region_name=region)
        
        # Get all user pools
        paginator = cognito_client.get_paginator('list_user_pools')
        page_iterator = paginator.paginate(MaxResults=60)
        
        all_user_pools = []
        for page in page_iterator:
            all_user_pools.extend(page.get('UserPools', []))
        
        if not all_user_pools:
            # No user pools found
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'Cognito',
                'resource_id': f'cognito-check-{region}',
                'status': 'COMPLIANT',
                'compliance_status': 'PASS',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                'recommendation': 'No Cognito User Pools found',
                'details': {
                    'total_user_pools': 0
                }
            }
            findings.append(finding)
            return findings
        
        # Check each user pool for WAF ACL attachment
        for user_pool in all_user_pools:
            user_pool_id = user_pool.get('Id', '')
            user_pool_name = user_pool.get('Name', 'unknown')
            
            try:
                # Get user pool details to check for domain
                user_pool_details = cognito_client.describe_user_pool(UserPoolId=user_pool_id)
                user_pool_data = user_pool_details.get('UserPool', {})
                
                # Check if user pool has a custom domain or hosted UI
                has_domain = False
                domain_name = None
                
                try:
                    # Check for custom domain
                    domain_response = cognito_client.describe_user_pool_domain(Domain=user_pool_id)
                    if domain_response.get('DomainDescription'):
                        has_domain = True
                        domain_name = domain_response['DomainDescription'].get('Domain')
                except:
                    # No custom domain found, check for hosted UI
                    pass
                
                # Check for WAF ACL association
                waf_acl_attached = False
                waf_acl_details = None
                
                if has_domain and domain_name:
                    try:
                        # Build the resource ARN for the Cognito domain
                        account_id = user_pool_id.split('_')[0] if '_' in user_pool_id else 'unknown'
                        resource_arn = f"arn:aws:cognito-idp:{region}:{account_id}:userpool/{user_pool_id}"
                        
                        # Check for WAF ACL association using WAFv2
                        waf_response = wafv2_client.get_web_acl_for_resource(ResourceArn=resource_arn)
                        if waf_response.get('WebACL'):
                            waf_acl_attached = True
                            waf_acl_details = {
                                'web_acl_arn': waf_response['WebACL'].get('ARN'),
                                'web_acl_name': waf_response['WebACL'].get('Name'),
                                'web_acl_id': waf_response['WebACL'].get('Id')
                            }
                    except Exception as e:
                        logger.debug(f"Could not check WAF ACL for user pool {user_pool_id}: {e}")
                
                # Determine compliance status
                if has_domain:
                    if waf_acl_attached:
                        status = 'COMPLIANT'
                        compliance_status = 'PASS'
                        recommendation = 'Cognito User Pool has WAF ACL properly attached'
                    else:
                        status = 'NON_COMPLIANT'
                        compliance_status = 'FAIL'
                        recommendation = 'Attach WAF ACL to Cognito User Pool domain for boundary protection'
                else:
                    # If no domain is configured, WAF is not applicable
                    status = 'COMPLIANT'
                    compliance_status = 'PASS'
                    recommendation = 'User Pool has no custom domain configured, WAF not applicable'
                
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'Cognito User Pool',
                    'resource_id': user_pool_id,
                    'status': status,
                    'compliance_status': compliance_status,
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                    'recommendation': recommendation,
                    'details': {
                        'user_pool_id': user_pool_id,
                        'user_pool_name': user_pool_name,
                        'has_domain': has_domain,
                        'domain_name': domain_name,
                        'waf_acl_attached': waf_acl_attached,
                        'waf_acl_details': waf_acl_details,
                        'status': user_pool_data.get('Status'),
                        'creation_date': user_pool_data.get('CreationDate', '').isoformat() if user_pool_data.get('CreationDate') else None,
                        'last_modified_date': user_pool_data.get('LastModifiedDate', '').isoformat() if user_pool_data.get('LastModifiedDate') else None
                    }
                }
                
                findings.append(finding)
                
            except Exception as e:
                logger.warning(f"Error checking WAF ACL for user pool {user_pool_id}: {e}")
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'Cognito User Pool',
                    'resource_id': user_pool_id,
                    'status': 'ERROR',
                    'compliance_status': 'ERROR',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                    'recommendation': 'Unable to check WAF ACL configuration due to access error',
                    'error': str(e),
                    'details': {
                        'user_pool_id': user_pool_id,
                        'user_pool_name': user_pool_name
                    }
                }
                findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in cognito_user_pool_waf_acl_attached check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'Cognito',
            'resource_id': f'cognito-error-{region}',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Attach WAF ACL to Cognito User Pool for boundary protection'),
            'error': str(e)
        })
        
    return findings

def cognito_user_pool_waf_acl_attached(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=cognito_user_pool_waf_acl_attached_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = cognito_user_pool_waf_acl_attached(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

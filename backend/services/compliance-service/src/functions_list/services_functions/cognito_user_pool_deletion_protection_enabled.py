#!/usr/bin/env python3
"""
kisa_isms_p_2023_aws - cognito_user_pool_deletion_protection_enabled

To ensure the availability of information systems, performance and capacity requirements must be defined, and the status must be continuously monitored. Procedures for detecting, recording, analyzing, recovering, and reporting in response to faults must be established and managed effectively.
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
                    'recommendation': entry.get('Recommendation', 'Enable deletion protection for Cognito User Pools to prevent accidental deletion')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'kisa_isms_p_2023_aws',
        'function_name': 'cognito_user_pool_deletion_protection_enabled',
        'id': '2.9.2',
        'name': 'Performance and Fault Management',
        'description': 'To ensure the availability of information systems, performance and capacity requirements must be defined, and the status must be continuously monitored. Procedures for detecting, recording, analyzing, recovering, and reporting in response to faults must be established and managed effectively.',
        'api_function': 'client=boto3.client(\'cognito-idp\')',
        'user_function': 'list_user_pools(), describe_user_pool()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Enable deletion protection for Cognito User Pools to prevent accidental deletion'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('cognito_user_pool_deletion_protection_enabled')

def cognito_user_pool_deletion_protection_enabled_check(cognito_idp_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for cognito_user_pool_deletion_protection_enabled.
    
    Args:
        cognito_idp_client: Boto3 Cognito IDP client (auto-created by framework)
        region (str): AWS region (auto-managed by framework)
        profile (str): AWS profile name (auto-managed by framework)
        logger: Logger instance (auto-configured by framework)
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    try:
        # List all user pools
        paginator = cognito_idp_client.get_paginator('list_user_pools')
        
        user_pools_found = False
        
        for page in paginator.paginate(MaxResults=60):
            user_pools = page.get('UserPools', [])
            
            for user_pool in user_pools:
                user_pools_found = True
                user_pool_id = user_pool.get('Id')
                user_pool_name = user_pool.get('Name', 'Unknown')
                
                try:
                    # Get detailed user pool information
                    response = cognito_idp_client.describe_user_pool(UserPoolId=user_pool_id)
                    user_pool_details = response.get('UserPool', {})
                    
                    # Check if deletion protection is enabled
                    deletion_protection = user_pool_details.get('DeletionProtection', 'INACTIVE')
                    
                    if deletion_protection == 'ACTIVE':
                        # Compliant - deletion protection is enabled
                        finding = {
                            'region': region,
                            'profile': profile,
                            'resource_type': 'CognitoUserPool',
                            'resource_id': user_pool_id,
                            'status': 'COMPLIANT',
                            'compliance_status': 'PASS',
                            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                            'recommendation': 'Deletion protection is properly enabled',
                            'details': {
                                'user_pool_name': user_pool_name,
                                'user_pool_id': user_pool_id,
                                'deletion_protection': deletion_protection,
                                'creation_date': user_pool_details.get('CreationDate', '').isoformat() if user_pool_details.get('CreationDate') else 'Unknown',
                                'last_modified_date': user_pool_details.get('LastModifiedDate', '').isoformat() if user_pool_details.get('LastModifiedDate') else 'Unknown'
                            }
                        }
                    else:
                        # Non-compliant - deletion protection is not enabled
                        finding = {
                            'region': region,
                            'profile': profile,
                            'resource_type': 'CognitoUserPool',
                            'resource_id': user_pool_id,
                            'status': 'NON_COMPLIANT',
                            'compliance_status': 'FAIL',
                            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable deletion protection for Cognito User Pools to prevent accidental deletion'),
                            'details': {
                                'user_pool_name': user_pool_name,
                                'user_pool_id': user_pool_id,
                                'deletion_protection': deletion_protection,
                                'issue': 'Deletion protection is not enabled',
                                'creation_date': user_pool_details.get('CreationDate', '').isoformat() if user_pool_details.get('CreationDate') else 'Unknown',
                                'last_modified_date': user_pool_details.get('LastModifiedDate', '').isoformat() if user_pool_details.get('LastModifiedDate') else 'Unknown'
                            }
                        }
                    
                    findings.append(finding)
                    
                except Exception as e:
                    logger.error(f"Error checking user pool {user_pool_id}: {e}")
                    findings.append({
                        'region': region,
                        'profile': profile,
                        'resource_type': 'CognitoUserPool',
                        'resource_id': user_pool_id,
                        'status': 'ERROR',
                        'compliance_status': 'ERROR',
                        'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                        'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable deletion protection for Cognito User Pools to prevent accidental deletion'),
                        'error': str(e),
                        'details': {
                            'user_pool_name': user_pool_name,
                            'user_pool_id': user_pool_id
                        }
                    })
        
        # If no user pools found, create an informational finding
        if not user_pools_found:
            findings.append({
                'region': region,
                'profile': profile,
                'resource_type': 'CognitoUserPool',
                'resource_id': 'No user pools found',
                'status': 'COMPLIANT',
                'compliance_status': 'PASS',
                'risk_level': 'INFO',
                'recommendation': 'No Cognito User Pools found in this region',
                'details': {
                    'message': 'No Cognito User Pools exist in this region'
                }
            })
        
    except Exception as e:
        logger.error(f"Error in cognito_user_pool_deletion_protection_enabled check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'CognitoUserPool',
            'resource_id': 'check-error',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable deletion protection for Cognito User Pools to prevent accidental deletion'),
            'error': str(e)
        })
        
    return findings

def cognito_user_pool_deletion_protection_enabled(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=cognito_user_pool_deletion_protection_enabled_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = cognito_user_pool_deletion_protection_enabled(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

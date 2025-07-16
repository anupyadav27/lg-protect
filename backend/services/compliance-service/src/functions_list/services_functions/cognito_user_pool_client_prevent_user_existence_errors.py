#!/usr/bin/env python3
"""
soc2_aws - cognito_user_pool_client_prevent_user_existence_errors

Restricts Access — The types of activities that can occur through a communication channel (for example, FTP site, router port) are restricted.
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
                    'recommendation': entry.get('Recommendation', 'Configure user existence error prevention for Cognito User Pool clients')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'soc2_aws',
        'function_name': 'cognito_user_pool_client_prevent_user_existence_errors',
        'id': 'cc_6_6',
        'name': 'CC6.6 The entity implements logical access security measures to protect against threats from sources outside its system boundaries',
        'description': 'Restricts Access — The types of activities that can occur through a communication channel (for example, FTP site, router port) are restricted.',
        'api_function': 'client=boto3.client(\'cognito-idp\')',
        'user_function': 'list_user_pool_clients()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Configure user existence error prevention for Cognito User Pool clients'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('cognito_user_pool_client_prevent_user_existence_errors')

def cognito_user_pool_client_prevent_user_existence_errors_check(cognito_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for cognito_user_pool_client_prevent_user_existence_errors.
    
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
        # Get all user pools first
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
                    'total_user_pools': 0,
                    'total_clients': 0
                }
            }
            findings.append(finding)
            return findings
        
        # Check each user pool's clients for user existence error prevention settings
        total_clients = 0
        for user_pool in all_user_pools:
            user_pool_id = user_pool.get('Id', '')
            user_pool_name = user_pool.get('Name', 'unknown')
            
            try:
                # Get all clients for this user pool
                clients_response = cognito_client.list_user_pool_clients(
                    UserPoolId=user_pool_id,
                    MaxResults=60
                )
                clients = clients_response.get('UserPoolClients', [])
                
                if not clients:
                    continue
                
                # Check each client for user existence error prevention settings
                for client in clients:
                    total_clients += 1
                    client_id = client.get('ClientId', '')
                    client_name = client.get('ClientName', 'unknown')
                    
                    try:
                        # Get detailed client configuration
                        client_details = cognito_client.describe_user_pool_client(
                            UserPoolId=user_pool_id,
                            ClientId=client_id
                        )
                        client_data = client_details.get('UserPoolClient', {})
                        
                        # Check user existence error prevention settings
                        prevent_user_existence_errors = client_data.get('PreventUserExistenceErrors', 'LEGACY')
                        
                        # Best practice is to set this to 'ENABLED' to prevent user enumeration attacks
                        user_existence_errors_prevented = prevent_user_existence_errors == 'ENABLED'
                        
                        # Check other relevant security settings
                        enable_token_revocation = client_data.get('EnableTokenRevocation', False)
                        auth_flows = client_data.get('ExplicitAuthFlows', [])
                        
                        if user_existence_errors_prevented:
                            status = 'COMPLIANT'
                            compliance_status = 'PASS'
                            recommendation = 'Cognito User Pool client properly prevents user existence errors'
                        else:
                            status = 'NON_COMPLIANT'
                            compliance_status = 'FAIL'
                            recommendation = 'Configure PreventUserExistenceErrors to ENABLED to prevent user enumeration attacks'
                        
                        finding = {
                            'region': region,
                            'profile': profile,
                            'resource_type': 'Cognito User Pool Client',
                            'resource_id': f'{user_pool_id}/{client_id}',
                            'status': status,
                            'compliance_status': compliance_status,
                            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                            'recommendation': recommendation,
                            'details': {
                                'user_pool_id': user_pool_id,
                                'user_pool_name': user_pool_name,
                                'client_id': client_id,
                                'client_name': client_name,
                                'prevent_user_existence_errors': prevent_user_existence_errors,
                                'user_existence_errors_prevented': user_existence_errors_prevented,
                                'enable_token_revocation': enable_token_revocation,
                                'explicit_auth_flows': auth_flows,
                                'supported_identity_providers': client_data.get('SupportedIdentityProviders', []),
                                'creation_date': client_data.get('CreationDate', '').isoformat() if client_data.get('CreationDate') else None,
                                'last_modified_date': client_data.get('LastModifiedDate', '').isoformat() if client_data.get('LastModifiedDate') else None
                            }
                        }
                        
                        findings.append(finding)
                        
                    except Exception as e:
                        logger.warning(f"Error checking client {client_id} in user pool {user_pool_id}: {e}")
                        finding = {
                            'region': region,
                            'profile': profile,
                            'resource_type': 'Cognito User Pool Client',
                            'resource_id': f'{user_pool_id}/{client_id}',
                            'status': 'ERROR',
                            'compliance_status': 'ERROR',
                            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                            'recommendation': 'Unable to check client user existence error prevention due to access error',
                            'error': str(e),
                            'details': {
                                'user_pool_id': user_pool_id,
                                'user_pool_name': user_pool_name,
                                'client_id': client_id,
                                'client_name': client_name
                            }
                        }
                        findings.append(finding)
                
            except Exception as e:
                logger.warning(f"Error listing clients for user pool {user_pool_id}: {e}")
        
        # If no clients were found across all user pools
        if total_clients == 0:
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'Cognito',
                'resource_id': f'cognito-clients-check-{region}',
                'status': 'COMPLIANT',
                'compliance_status': 'PASS',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                'recommendation': 'No Cognito User Pool clients found',
                'details': {
                    'total_user_pools': len(all_user_pools),
                    'total_clients': 0
                }
            }
            findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in cognito_user_pool_client_prevent_user_existence_errors check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'Cognito',
            'resource_id': f'cognito-error-{region}',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Configure user existence error prevention for Cognito User Pool clients'),
            'error': str(e)
        })
        
    return findings

def cognito_user_pool_client_prevent_user_existence_errors(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=cognito_user_pool_client_prevent_user_existence_errors_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = cognito_user_pool_client_prevent_user_existence_errors(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

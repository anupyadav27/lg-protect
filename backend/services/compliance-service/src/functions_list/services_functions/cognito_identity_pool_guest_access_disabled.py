#!/usr/bin/env python3
"""
kisa_isms_p_2023_aws - cognito_identity_pool_guest_access_disabled

Managing information systems and handling personal information outside of protected areas is, in principle, prohibited. However, if remote access is allowed for unavoidable reasons such as telecommuting, incident response, or remote collaboration, protective measures must be established and implemented, including approval from responsible personnel, designation of access devices, setting access scope and duration, enhanced authentication, encrypted communication, and securing access devices (e.g., antivirus, patches).
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
                    'risk_level': entry.get('Risk Level', 'HIGH'),
                    'recommendation': entry.get('Recommendation', 'Disable guest access for Cognito Identity Pools to enforce authentication')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'kisa_isms_p_2023_aws',
        'function_name': 'cognito_identity_pool_guest_access_disabled',
        'id': '2.6.6',
        'name': 'Remote Access Control',
        'description': 'Managing information systems and handling personal information outside of protected areas is, in principle, prohibited. However, if remote access is allowed for unavoidable reasons such as telecommuting, incident response, or remote collaboration, protective measures must be established and implemented, including approval from responsible personnel, designation of access devices, setting access scope and duration, enhanced authentication, encrypted communication, and securing access devices (e.g., antivirus, patches).',
        'api_function': 'client = boto3.client(\'cognito-identity\')',
        'user_function': 'list_identity_pools(), describe_identity_pool()',
        'risk_level': 'HIGH',
        'recommendation': 'Disable guest access for Cognito Identity Pools to enforce authentication'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('cognito_identity_pool_guest_access_disabled')

def cognito_identity_pool_guest_access_disabled_check(cognito_identity_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for cognito_identity_pool_guest_access_disabled.
    
    Args:
        cognito_identity_client: Boto3 Cognito Identity client (auto-created by framework)
        region (str): AWS region (auto-managed by framework)
        profile (str): AWS profile name (auto-managed by framework)
        logger: Logger instance (auto-configured by framework)
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    try:
        # List all identity pools
        paginator = cognito_identity_client.get_paginator('list_identity_pools')
        
        identity_pools_found = False
        
        for page in paginator.paginate(MaxResults=60):
            identity_pools = page.get('IdentityPools', [])
            
            for identity_pool in identity_pools:
                identity_pools_found = True
                identity_pool_id = identity_pool.get('IdentityPoolId')
                identity_pool_name = identity_pool.get('IdentityPoolName', 'Unknown')
                
                try:
                    # Get detailed identity pool information
                    response = cognito_identity_client.describe_identity_pool(
                        IdentityPoolId=identity_pool_id
                    )
                    
                    # Check if guest access (unauthenticated access) is disabled
                    allow_unauthenticated_identities = response.get('AllowUnauthenticatedIdentities', True)
                    
                    if not allow_unauthenticated_identities:
                        # Compliant - guest access is disabled
                        finding = {
                            'region': region,
                            'profile': profile,
                            'resource_type': 'Cognito Identity Pool',
                            'resource_id': identity_pool_id,
                            'status': 'COMPLIANT',
                            'compliance_status': 'PASS',
                            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                            'recommendation': 'Guest access is properly disabled',
                            'details': {
                                'identity_pool_name': identity_pool_name,
                                'identity_pool_id': identity_pool_id,
                                'allow_unauthenticated_identities': allow_unauthenticated_identities,
                                'cognito_identity_providers': response.get('CognitoIdentityProviders', []),
                                'supported_login_providers': list(response.get('SupportedLoginProviders', {}).keys()) if response.get('SupportedLoginProviders') else []
                            }
                        }
                    else:
                        # Non-compliant - guest access is enabled
                        finding = {
                            'region': region,
                            'profile': profile,
                            'resource_type': 'Cognito Identity Pool',
                            'resource_id': identity_pool_id,
                            'status': 'NON_COMPLIANT',
                            'compliance_status': 'FAIL',
                            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Disable guest access for Cognito Identity Pools to enforce authentication'),
                            'details': {
                                'identity_pool_name': identity_pool_name,
                                'identity_pool_id': identity_pool_id,
                                'allow_unauthenticated_identities': allow_unauthenticated_identities,
                                'issue': 'Guest access (unauthenticated identities) is enabled',
                                'security_risk': 'Allows anonymous access without authentication',
                                'cognito_identity_providers': response.get('CognitoIdentityProviders', []),
                                'supported_login_providers': list(response.get('SupportedLoginProviders', {}).keys()) if response.get('SupportedLoginProviders') else []
                            }
                        }
                    
                    findings.append(finding)
                    
                except Exception as e:
                    logger.error(f"Error checking identity pool {identity_pool_id}: {e}")
                    findings.append({
                        'region': region,
                        'profile': profile,
                        'resource_type': 'Cognito Identity Pool',
                        'resource_id': identity_pool_id,
                        'status': 'ERROR',
                        'compliance_status': 'ERROR',
                        'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                        'recommendation': COMPLIANCE_DATA.get('recommendation', 'Disable guest access for Cognito Identity Pools to enforce authentication'),
                        'error': str(e),
                        'details': {
                            'identity_pool_name': identity_pool_name,
                            'identity_pool_id': identity_pool_id
                        }
                    })
        
        # If no identity pools found, create an informational finding
        if not identity_pools_found:
            findings.append({
                'region': region,
                'profile': profile,
                'resource_type': 'Cognito',
                'resource_id': f'cognito-identity-check-{region}',
                'status': 'COMPLIANT',
                'compliance_status': 'PASS',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                'recommendation': 'No Cognito Identity Pools found',
                'details': {
                    'total_identity_pools': 0
                }
            })
        
    except Exception as e:
        logger.error(f"Error in cognito_identity_pool_guest_access_disabled check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'Cognito',
            'resource_id': f'cognito-identity-error-{region}',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Disable guest access for Cognito Identity Pools to enforce authentication'),
            'error': str(e)
        })
        
    return findings

def cognito_identity_pool_guest_access_disabled(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=cognito_identity_pool_guest_access_disabled_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = cognito_identity_pool_guest_access_disabled(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

#!/usr/bin/env python3
"""
soc2_aws - cognito_user_pool_password_policy_symbol

Protects Identification and Authentication Credentials — Identification and authentication credentials are protected during transmission outside its system boundaries.
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
                    'recommendation': entry.get('Recommendation', 'Configure password policy to require symbols')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'soc2_aws',
        'function_name': 'cognito_user_pool_password_policy_symbol',
        'id': 'cc_6_6',
        'name': 'CC6.6 The entity implements logical access security measures to protect against threats from sources outside its system boundaries',
        'description': 'Protects Identification and Authentication Credentials — Identification and authentication credentials are protected during transmission outside its system boundaries.',
        'api_function': 'client=boto3.client(\'cognito-idp\')',
        'user_function': 'list_user_pools()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Configure password policy to require symbols'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('cognito_user_pool_password_policy_symbol')

def cognito_user_pool_password_policy_symbol_check(cognito_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for cognito_user_pool_password_policy_symbol.
    
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
        
        # Check each user pool for password policy symbol requirement
        for user_pool in all_user_pools:
            user_pool_id = user_pool.get('Id', '')
            user_pool_name = user_pool.get('Name', 'unknown')
            
            try:
                # Get detailed user pool configuration
                user_pool_details = cognito_client.describe_user_pool(UserPoolId=user_pool_id)
                user_pool_data = user_pool_details.get('UserPool', {})
                
                # Check password policy
                password_policy = user_pool_data.get('Policies', {}).get('PasswordPolicy', {})
                
                # Check if symbol requirement is enabled
                require_symbols = password_policy.get('RequireSymbols', False)
                
                # Get other password policy details for context
                minimum_length = password_policy.get('MinimumLength', 8)
                require_lowercase = password_policy.get('RequireLowercase', False)
                require_uppercase = password_policy.get('RequireUppercase', False)
                require_numbers = password_policy.get('RequireNumbers', False)
                
                if require_symbols:
                    status = 'COMPLIANT'
                    compliance_status = 'PASS'
                    recommendation = 'Cognito User Pool password policy properly requires symbols'
                else:
                    status = 'NON_COMPLIANT'
                    compliance_status = 'FAIL'
                    recommendation = 'Enable symbol requirement in password policy'
                
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
                        'require_symbols': require_symbols,
                        'password_policy': {
                            'minimum_length': minimum_length,
                            'require_lowercase': require_lowercase,
                            'require_uppercase': require_uppercase,
                            'require_numbers': require_numbers,
                            'require_symbols': require_symbols
                        },
                        'status': user_pool_data.get('Status'),
                        'creation_date': user_pool_data.get('CreationDate', '').isoformat() if user_pool_data.get('CreationDate') else None,
                        'last_modified_date': user_pool_data.get('LastModifiedDate', '').isoformat() if user_pool_data.get('LastModifiedDate') else None
                    }
                }
                
                findings.append(finding)
                
            except Exception as e:
                logger.warning(f"Error checking password policy for user pool {user_pool_id}: {e}")
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'Cognito User Pool',
                    'resource_id': user_pool_id,
                    'status': 'ERROR',
                    'compliance_status': 'ERROR',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                    'recommendation': 'Unable to check password policy configuration due to access error',
                    'error': str(e),
                    'details': {
                        'user_pool_id': user_pool_id,
                        'user_pool_name': user_pool_name
                    }
                }
                findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in cognito_user_pool_password_policy_symbol check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'Cognito',
            'resource_id': f'cognito-error-{region}',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Configure password policy to require symbols'),
            'error': str(e)
        })
        
    return findings

def cognito_user_pool_password_policy_symbol(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=cognito_user_pool_password_policy_symbol_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = cognito_user_pool_password_policy_symbol(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

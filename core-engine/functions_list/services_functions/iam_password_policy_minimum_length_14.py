#!/usr/bin/env python3
"""
cis_4.0_aws - iam_password_policy_minimum_length_14

Ensure IAM password policy requires minimum length of 14 or greater
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
        'compliance_name': 'cis_4.0_aws',
        'function_name': 'iam_password_policy_minimum_length_14',
        'id': '1.8',
        'name': 'Ensure IAM password policy requires minimum length of 14 or greater',
        'description': 'Ensure IAM password policy requires minimum length of 14 or greater',
        'api_function': 'client = boto3.client("iam")',
        'user_function': 'get_account_password_policy()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Configure IAM password policy to require minimum length of 14 characters'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('iam_password_policy_minimum_length_14')

def iam_password_policy_minimum_length_14_check(iam_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for iam_password_policy_minimum_length_14.
    
    Args:
        iam_client: Boto3 IAM client (auto-created by framework)
        region (str): AWS region (auto-managed by framework)
        profile (str): AWS profile name (auto-managed by framework)
        logger: Logger instance (auto-configured by framework)
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    try:
        logger.info(f"Checking IAM password policy minimum length in region {region}")
        
        # Note: IAM is a global service, but we check in each region for consistency
        # Get the account password policy
        try:
            policy_response = iam_client.get_account_password_policy()
            password_policy = policy_response.get('PasswordPolicy', {})
            
            # Extract password policy settings
            minimum_password_length = password_policy.get('MinimumPasswordLength', 0)
            require_symbols = password_policy.get('RequireSymbols', False)
            require_numbers = password_policy.get('RequireNumbers', False)
            require_uppercase_characters = password_policy.get('RequireUppercaseCharacters', False)
            require_lowercase_characters = password_policy.get('RequireLowercaseCharacters', False)
            allow_users_to_change_password = password_policy.get('AllowUsersToChangePassword', False)
            expire_passwords = password_policy.get('ExpirePasswords', False)
            max_password_age = password_policy.get('MaxPasswordAge', None)
            password_reuse_prevention = password_policy.get('PasswordReusePrevention', None)
            hard_expiry = password_policy.get('HardExpiry', False)
            
            # Check if minimum password length is 14 or greater
            if minimum_password_length >= 14:
                # Compliant: Password policy requires minimum length of 14 or greater
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'IAM Account Password Policy',
                    'resource_id': 'account-password-policy',
                    'status': 'COMPLIANT',
                    'compliance_status': 'PASS',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Password policy minimum length is properly configured'),
                    'details': {
                        'minimum_password_length': minimum_password_length,
                        'required_minimum': 14,
                        'compliance_met': True,
                        'password_policy_settings': {
                            'require_symbols': require_symbols,
                            'require_numbers': require_numbers,
                            'require_uppercase_characters': require_uppercase_characters,
                            'require_lowercase_characters': require_lowercase_characters,
                            'allow_users_to_change_password': allow_users_to_change_password,
                            'expire_passwords': expire_passwords,
                            'max_password_age': max_password_age,
                            'password_reuse_prevention': password_reuse_prevention,
                            'hard_expiry': hard_expiry
                        }
                    }
                }
            else:
                # Non-compliant: Password policy minimum length is less than 14
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'IAM Account Password Policy',
                    'resource_id': 'account-password-policy',
                    'status': 'NON_COMPLIANT',
                    'compliance_status': 'FAIL',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Update password policy to require minimum length of 14 characters'),
                    'details': {
                        'minimum_password_length': minimum_password_length,
                        'required_minimum': 14,
                        'compliance_met': False,
                        'issue': f'Password policy minimum length is {minimum_password_length}, which is less than the required 14 characters',
                        'security_risk': 'Shorter passwords are more vulnerable to brute force attacks and password cracking',
                        'remediation_steps': [
                            'Access the AWS IAM console',
                            'Navigate to Account settings > Password policy',
                            'Set "Minimum password length" to 14 or greater',
                            'Consider enabling additional password complexity requirements',
                            'Review and update password policy documentation',
                            'Communicate password policy changes to users'
                        ],
                        'password_policy_settings': {
                            'require_symbols': require_symbols,
                            'require_numbers': require_numbers,
                            'require_uppercase_characters': require_uppercase_characters,
                            'require_lowercase_characters': require_lowercase_characters,
                            'allow_users_to_change_password': allow_users_to_change_password,
                            'expire_passwords': expire_passwords,
                            'max_password_age': max_password_age,
                            'password_reuse_prevention': password_reuse_prevention,
                            'hard_expiry': hard_expiry
                        }
                    }
                }
            
            findings.append(finding)
            
        except iam_client.exceptions.NoSuchEntityException:
            # No password policy exists
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'IAM Account Password Policy',
                'resource_id': 'account-password-policy',
                'status': 'NON_COMPLIANT',
                'compliance_status': 'FAIL',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                'recommendation': COMPLIANCE_DATA.get('recommendation', 'Create a password policy with minimum length of 14 characters'),
                'details': {
                    'minimum_password_length': None,
                    'required_minimum': 14,
                    'compliance_met': False,
                    'issue': 'No password policy is configured for the AWS account',
                    'security_risk': 'Without a password policy, users can create weak passwords that are vulnerable to attacks',
                    'remediation_steps': [
                        'Access the AWS IAM console',
                        'Navigate to Account settings > Password policy',
                        'Create a new password policy',
                        'Set "Minimum password length" to 14 or greater',
                        'Enable additional password complexity requirements',
                        'Consider enabling password expiration and reuse prevention',
                        'Document and communicate the new password policy'
                    ]
                }
            }
            findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in iam_password_policy_minimum_length_14 check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'IAM Account Password Policy',
            'resource_id': 'account-password-policy',
            'status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Review and remediate as needed'),
            'error': str(e)
        })
        
    return findings

def iam_password_policy_minimum_length_14(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=iam_password_policy_minimum_length_14_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = iam_password_policy_minimum_length_14(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

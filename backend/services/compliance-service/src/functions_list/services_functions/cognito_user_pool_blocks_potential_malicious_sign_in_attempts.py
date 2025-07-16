#!/usr/bin/env python3
"""
soc2_aws - cognito_user_pool_blocks_potential_malicious_sign_in_attempts

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
                    'risk_level': entry.get('Risk Level', 'HIGH'),
                    'recommendation': entry.get('Recommendation', 'Enable malicious sign-in attempt protection for Cognito User Pool')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'soc2_aws',
        'function_name': 'cognito_user_pool_blocks_potential_malicious_sign_in_attempts',
        'id': 'cc_6_6',
        'name': 'CC6.6 The entity implements logical access security measures to protect against threats from sources outside its system boundaries',
        'description': 'Implements Boundary Protection Systems — Boundary protection systems (for example, firewalls, demilitarized zones, and intrusion detection systems) are implemented to protect external access points from attempts and unauthorized access and are monitored to detect such attempts.',
        'api_function': 'client=boto3.client(\'cognito-idp\')',
        'user_function': 'list_user_pools()',
        'risk_level': 'HIGH',
        'recommendation': 'Enable malicious sign-in attempt protection for Cognito User Pool'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('cognito_user_pool_blocks_potential_malicious_sign_in_attempts')

def cognito_user_pool_blocks_potential_malicious_sign_in_attempts_check(cognito_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for cognito_user_pool_blocks_potential_malicious_sign_in_attempts.
    
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
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                'recommendation': 'No Cognito User Pools found',
                'details': {
                    'total_user_pools': 0
                }
            }
            findings.append(finding)
            return findings
        
        # Check each user pool for malicious sign-in attempt protection
        for user_pool in all_user_pools:
            user_pool_id = user_pool.get('Id', '')
            user_pool_name = user_pool.get('Name', 'unknown')
            
            try:
                # Get detailed user pool configuration
                user_pool_details = cognito_client.describe_user_pool(UserPoolId=user_pool_id)
                user_pool_data = user_pool_details.get('UserPool', {})
                
                # Check advanced security features for malicious sign-in protection
                user_pool_add_ons = user_pool_data.get('UserPoolAddOns', {})
                advanced_security_mode = user_pool_add_ons.get('AdvancedSecurityMode', 'OFF')
                
                # To have malicious sign-in protection, advanced security must be enabled
                advanced_security_enabled = advanced_security_mode in ['AUDIT', 'ENFORCED']
                
                # Check if there are risk configuration settings for account takeover
                risk_configuration_available = False
                malicious_attempts_blocked = False
                account_takeover_actions = {}
                
                if advanced_security_enabled:
                    try:
                        # Check risk configuration for this user pool
                        risk_config_response = cognito_client.describe_risk_configuration(
                            UserPoolId=user_pool_id
                        )
                        risk_config = risk_config_response.get('RiskConfiguration', {})
                        
                        # Check account takeover risk configuration
                        account_takeover_risk_config = risk_config.get('AccountTakeoverRiskConfiguration', {})
                        
                        if account_takeover_risk_config:
                            risk_configuration_available = True
                            actions = account_takeover_risk_config.get('Actions', {})
                            
                            # Check different risk level actions
                            low_action = actions.get('LowAction', {}).get('EventAction', 'NO_ACTION')
                            medium_action = actions.get('MediumAction', {}).get('EventAction', 'NO_ACTION')
                            high_action = actions.get('HighAction', {}).get('EventAction', 'NO_ACTION')
                            
                            account_takeover_actions = {
                                'low_action': low_action,
                                'medium_action': medium_action,
                                'high_action': high_action
                            }
                            
                            # Check if at least one risk level has blocking enabled
                            blocking_actions = ['BLOCK', 'MFA_IF_CONFIGURED', 'MFA_REQUIRED']
                            malicious_attempts_blocked = any(
                                action in blocking_actions 
                                for action in [low_action, medium_action, high_action]
                            )
                    
                    except Exception as e:
                        logger.debug(f"Could not retrieve risk configuration for user pool {user_pool_id}: {e}")
                
                # Determine compliance status
                if advanced_security_enabled and malicious_attempts_blocked:
                    status = 'COMPLIANT'
                    compliance_status = 'PASS'
                    recommendation = 'Cognito User Pool properly blocks potential malicious sign-in attempts'
                elif advanced_security_enabled and risk_configuration_available:
                    status = 'NON_COMPLIANT'
                    compliance_status = 'FAIL'
                    recommendation = 'Configure account takeover protection to block malicious sign-in attempts'
                elif advanced_security_enabled:
                    status = 'NON_COMPLIANT'
                    compliance_status = 'FAIL'
                    recommendation = 'Configure risk-based authentication to protect against malicious sign-in attempts'
                else:
                    status = 'NON_COMPLIANT'
                    compliance_status = 'FAIL'
                    recommendation = 'Enable Advanced Security Features and configure account takeover protection'
                
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'Cognito User Pool',
                    'resource_id': user_pool_id,
                    'status': status,
                    'compliance_status': compliance_status,
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                    'recommendation': recommendation,
                    'details': {
                        'user_pool_id': user_pool_id,
                        'user_pool_name': user_pool_name,
                        'advanced_security_mode': advanced_security_mode,
                        'advanced_security_enabled': advanced_security_enabled,
                        'risk_configuration_available': risk_configuration_available,
                        'malicious_attempts_blocked': malicious_attempts_blocked,
                        'account_takeover_actions': account_takeover_actions,
                        'status': user_pool_data.get('Status'),
                        'creation_date': user_pool_data.get('CreationDate', '').isoformat() if user_pool_data.get('CreationDate') else None,
                        'last_modified_date': user_pool_data.get('LastModifiedDate', '').isoformat() if user_pool_data.get('LastModifiedDate') else None
                    }
                }
                
                findings.append(finding)
                
            except Exception as e:
                logger.warning(f"Error checking malicious sign-in protection for user pool {user_pool_id}: {e}")
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'Cognito User Pool',
                    'resource_id': user_pool_id,
                    'status': 'ERROR',
                    'compliance_status': 'ERROR',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                    'recommendation': 'Unable to check malicious sign-in protection due to access error',
                    'error': str(e),
                    'details': {
                        'user_pool_id': user_pool_id,
                        'user_pool_name': user_pool_name
                    }
                }
                findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in cognito_user_pool_blocks_potential_malicious_sign_in_attempts check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'Cognito',
            'resource_id': f'cognito-error-{region}',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable malicious sign-in attempt protection for Cognito User Pool'),
            'error': str(e)
        })
        
    return findings

def cognito_user_pool_blocks_potential_malicious_sign_in_attempts(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=cognito_user_pool_blocks_potential_malicious_sign_in_attempts_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = cognito_user_pool_blocks_potential_malicious_sign_in_attempts(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

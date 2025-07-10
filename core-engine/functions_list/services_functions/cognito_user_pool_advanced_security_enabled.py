#!/usr/bin/env python3
"""
iso27001_2022_aws - cognito_user_pool_advanced_security_enabled

Information processing facilities should be implemented with redundancy sufficient to meet availability requirements.
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
                    'recommendation': entry.get('Recommendation', 'Enable advanced security for Cognito User Pool')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'iso27001_2022_aws',
        'function_name': 'cognito_user_pool_advanced_security_enabled',
        'id': 'A.8.14',
        'name': 'Redundancy of information processing facilities',
        'description': 'Information processing facilities should be implemented with redundancy sufficient to meet availability requirements.',
        'api_function': 'client=boto3.client(\'cognito-idp\')',
        'user_function': 'list_user_pools()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Enable advanced security for Cognito User Pool'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('cognito_user_pool_advanced_security_enabled')

def cognito_user_pool_advanced_security_enabled_check(cognito_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for cognito_user_pool_advanced_security_enabled.
    
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
        
        # Check each user pool for advanced security configuration
        for user_pool in all_user_pools:
            user_pool_id = user_pool.get('Id', '')
            user_pool_name = user_pool.get('Name', 'unknown')
            
            try:
                # Get detailed user pool configuration
                user_pool_details = cognito_client.describe_user_pool(UserPoolId=user_pool_id)
                user_pool_data = user_pool_details.get('UserPool', {})
                
                # Check advanced security features
                user_pool_add_ons = user_pool_data.get('UserPoolAddOns', {})
                advanced_security_mode = user_pool_add_ons.get('AdvancedSecurityMode', 'OFF')
                
                # Advanced security should be either 'AUDIT' or 'ENFORCED'
                advanced_security_enabled = advanced_security_mode in ['AUDIT', 'ENFORCED']
                
                if advanced_security_enabled:
                    status = 'COMPLIANT'
                    compliance_status = 'PASS'
                    recommendation = f'Cognito User Pool has advanced security enabled ({advanced_security_mode})'
                else:
                    status = 'NON_COMPLIANT'
                    compliance_status = 'FAIL'
                    recommendation = 'Enable Advanced Security Features (AUDIT or ENFORCED mode) for Cognito User Pool'
                
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
                        'advanced_security_mode': advanced_security_mode,
                        'advanced_security_enabled': advanced_security_enabled,
                        'user_pool_add_ons': user_pool_add_ons,
                        'status': user_pool_data.get('Status'),
                        'creation_date': user_pool_data.get('CreationDate', '').isoformat() if user_pool_data.get('CreationDate') else None,
                        'last_modified_date': user_pool_data.get('LastModifiedDate', '').isoformat() if user_pool_data.get('LastModifiedDate') else None
                    }
                }
                
                findings.append(finding)
                
            except Exception as e:
                logger.warning(f"Error checking advanced security for user pool {user_pool_id}: {e}")
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'Cognito User Pool',
                    'resource_id': user_pool_id,
                    'status': 'ERROR',
                    'compliance_status': 'ERROR',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                    'recommendation': 'Unable to check advanced security configuration due to access error',
                    'error': str(e),
                    'details': {
                        'user_pool_id': user_pool_id,
                        'user_pool_name': user_pool_name
                    }
                }
                findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in cognito_user_pool_advanced_security_enabled check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'Cognito',
            'resource_id': f'cognito-error-{region}',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable advanced security for Cognito User Pool'),
            'error': str(e)
        })
        
    return findings

def cognito_user_pool_advanced_security_enabled(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=cognito_user_pool_advanced_security_enabled_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = cognito_user_pool_advanced_security_enabled(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

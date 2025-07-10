#!/usr/bin/env python3
"""
iso27001_2022_aws - kms_key_not_publicly_accessible

Rules for the effective use of cryptography, including cryptographic key management, should be defined and implemented.
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
                    'recommendation': entry.get('Recommendation', 'Ensure KMS keys are not publicly accessible')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'iso27001_2022_aws',
        'function_name': 'kms_key_not_publicly_accessible',
        'id': 'A.10.1.2',
        'name': 'Key Management',
        'description': 'Rules for the effective use of cryptography, including cryptographic key management, should be defined and implemented.',
        'api_function': 'client = boto3.client("kms")',
        'user_function': 'list_keys(), get_key_policy()',
        'risk_level': 'HIGH',
        'recommendation': 'Ensure KMS keys are not publicly accessible'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('kms_key_not_publicly_accessible')

def kms_key_not_publicly_accessible_check(kms_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for kms_key_not_publicly_accessible.
    
    Args:
        kms_client: Boto3 KMS client (auto-created by framework)
        region (str): AWS region (auto-managed by framework)
        profile (str): AWS profile name (auto-managed by framework)
        logger: Logger instance (auto-configured by framework)
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    try:
        logger.info("Checking KMS keys for public accessibility...")
        
        # Get all customer-managed KMS keys
        response = kms_client.list_keys()
        keys = response.get('Keys', [])
        
        if not keys:
            logger.info("No KMS keys found in this region")
            return findings
        
        for key in keys:
            key_id = key.get('KeyId', 'Unknown')
            
            try:
                # Get detailed key information
                key_details = kms_client.describe_key(KeyId=key_id)
                key_metadata = key_details.get('KeyMetadata', {})
                
                key_manager = key_metadata.get('KeyManager', 'UNKNOWN')
                key_usage = key_metadata.get('KeyUsage', 'UNKNOWN')
                key_state = key_metadata.get('KeyState', 'UNKNOWN')
                
                # Skip AWS-managed keys as they are handled by AWS
                if key_manager == 'AWS':
                    continue
                
                # Get key policy to check for public access
                try:
                    policy_response = kms_client.get_key_policy(
                        KeyId=key_id,
                        PolicyName='default'
                    )
                    policy_document = json.loads(policy_response.get('Policy', '{}'))
                    
                    # Check for public access in policy
                    is_publicly_accessible = False
                    public_statements = []
                    
                    statements = policy_document.get('Statement', [])
                    for statement in statements:
                        if isinstance(statement, dict):
                            principal = statement.get('Principal', {})
                            
                            # Check for wildcard principals that allow public access
                            if principal == '*' or principal == {'AWS': '*'}:
                                is_publicly_accessible = True
                                public_statements.append({
                                    'effect': statement.get('Effect', 'Unknown'),
                                    'principal': principal,
                                    'action': statement.get('Action', [])
                                })
                            elif isinstance(principal, dict) and 'AWS' in principal:
                                aws_principals = principal['AWS']
                                if isinstance(aws_principals, list):
                                    for aws_principal in aws_principals:
                                        if aws_principal == '*':
                                            is_publicly_accessible = True
                                            public_statements.append({
                                                'effect': statement.get('Effect', 'Unknown'),
                                                'principal': aws_principal,
                                                'action': statement.get('Action', [])
                                            })
                                elif aws_principals == '*':
                                    is_publicly_accessible = True
                                    public_statements.append({
                                        'effect': statement.get('Effect', 'Unknown'),
                                        'principal': aws_principals,
                                        'action': statement.get('Action', [])
                                    })
                    
                    # Determine compliance status
                    if is_publicly_accessible:
                        status = 'NON_COMPLIANT'
                        compliance_status = 'FAIL'
                        message = f"KMS key has public access through {len(public_statements)} policy statement(s)"
                    else:
                        status = 'COMPLIANT'
                        compliance_status = 'PASS'
                        message = "KMS key is not publicly accessible"
                    
                    finding = {
                        'region': region,
                        'profile': profile,
                        'resource_type': 'KMS Key',
                        'resource_id': key_id,
                        'status': status,
                        'compliance_status': compliance_status,
                        'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                        'recommendation': COMPLIANCE_DATA.get('recommendation', 'Ensure KMS keys are not publicly accessible'),
                        'details': {
                            'key_id': key_id,
                            'key_arn': key_metadata.get('Arn', 'Unknown'),
                            'key_manager': key_manager,
                            'key_usage': key_usage,
                            'key_state': key_state,
                            'is_publicly_accessible': is_publicly_accessible,
                            'public_statements_count': len(public_statements),
                            'public_statements': public_statements,
                            'created_date': str(key_metadata.get('CreationDate', 'Unknown')),
                            'description': key_metadata.get('Description', 'No description'),
                            'message': message
                        }
                    }
                    
                except Exception as policy_error:
                    logger.warning(f"Could not retrieve policy for key {key_id}: {policy_error}")
                    finding = {
                        'region': region,
                        'profile': profile,
                        'resource_type': 'KMS Key',
                        'resource_id': key_id,
                        'status': 'ERROR',
                        'compliance_status': 'ERROR',
                        'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                        'recommendation': COMPLIANCE_DATA.get('recommendation', 'Ensure KMS keys are not publicly accessible'),
                        'error': str(policy_error),
                        'details': {
                            'key_id': key_id,
                            'key_arn': key_metadata.get('Arn', 'Unknown'),
                            'key_manager': key_manager,
                            'key_usage': key_usage,
                            'key_state': key_state,
                            'error_message': str(policy_error),
                            'message': f"Could not verify public access for key {key_id}"
                        }
                    }
                
                findings.append(finding)
                
            except Exception as e:
                logger.error(f"Error describing key {key_id}: {e}")
                findings.append({
                    'region': region,
                    'profile': profile,
                    'resource_type': 'KMS Key',
                    'resource_id': key_id,
                    'status': 'ERROR',
                    'compliance_status': 'ERROR',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Ensure KMS keys are not publicly accessible'),
                    'error': str(e),
                    'details': {
                        'key_id': key_id,
                        'error_message': str(e)
                    }
                })
            
    except Exception as e:
        logger.error(f"Error in kms_key_not_publicly_accessible check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'KMS Key',
            'resource_id': 'Unknown',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Ensure KMS keys are not publicly accessible'),
            'error': str(e),
            'details': {
                'error_message': str(e),
                'check_type': 'kms_key_not_publicly_accessible'
            }
        })
        
    return findings

def kms_key_not_publicly_accessible(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=kms_key_not_publicly_accessible_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = kms_key_not_publicly_accessible(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

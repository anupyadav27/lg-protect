#!/usr/bin/env python3
"""
nist_csf_1.1_aws - secretsmanager_automatic_rotation_enabled

Identities and credentials are issued, managed, verified, revoked, and audited for authorized devices, users and processes.
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
        'compliance_name': 'nist_csf_1.1_aws',
        'function_name': 'secretsmanager_automatic_rotation_enabled',
        'id': 'PR.AC-1',
        'name': 'Secrets Manager secrets should have automatic rotation enabled',
        'description': 'Identities and credentials are issued, managed, verified, revoked, and audited for authorized devices, users and processes',
        'api_function': 'client = boto3.client("secretsmanager")',
        'user_function': 'list_secrets(), describe_secret()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Enable automatic rotation for Secrets Manager secrets to maintain credential security'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('secretsmanager_automatic_rotation_enabled')

def secretsmanager_automatic_rotation_enabled_check(secretsmanager_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for secretsmanager_automatic_rotation_enabled.
    
    Args:
        secretsmanager_client: Boto3 Secrets Manager client (auto-created by framework)
        region (str): AWS region (auto-managed by framework)
        profile (str): AWS profile name (auto-managed by framework)
        logger: Logger instance (auto-configured by framework)
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    try:
        logger.info(f"Checking Secrets Manager automatic rotation in region {region}")
        
        # Get all secrets
        paginator = secretsmanager_client.get_paginator('list_secrets')
        
        for page in paginator.paginate():
            secrets = page.get('SecretList', [])
            
            if not secrets:
                continue
            
            # Check each secret for automatic rotation
            for secret in secrets:
                secret_name = secret.get('Name', 'unknown')
                secret_arn = secret.get('ARN', 'unknown')
                
                try:
                    # Get detailed secret information
                    secret_details = secretsmanager_client.describe_secret(SecretId=secret_name)
                    
                    rotation_enabled = secret_details.get('RotationEnabled', False)
                    rotation_lambda_arn = secret_details.get('RotationLambdaARN', '')
                    rotation_rules = secret_details.get('RotationRules', {})
                    
                    # Additional secret metadata
                    created_date = secret_details.get('CreatedDate', '')
                    last_accessed_date = secret_details.get('LastAccessedDate', '')
                    last_changed_date = secret_details.get('LastChangedDate', '')
                    last_rotated_date = secret_details.get('LastRotatedDate', '')
                    next_rotation_date = secret_details.get('NextRotationDate', '')
                    kms_key_id = secret_details.get('KmsKeyId', '')
                    replica_regions = secret_details.get('ReplicationStatus', [])
                    
                    # Get rotation interval
                    automatically_after_days = rotation_rules.get('AutomaticallyAfterDays', 0) if rotation_rules else 0
                    
                    if rotation_enabled:
                        # Compliant: Automatic rotation is enabled
                        finding = {
                            'region': region,
                            'profile': profile,
                            'resource_type': 'Secrets Manager Secret',
                            'resource_id': secret_name,
                            'status': 'COMPLIANT',
                            'compliance_status': 'PASS',
                            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Automatic rotation is properly configured'),
                            'details': {
                                'secret_name': secret_name,
                                'secret_arn': secret_arn,
                                'rotation_enabled': rotation_enabled,
                                'rotation_lambda_arn': rotation_lambda_arn,
                                'rotation_interval_days': automatically_after_days,
                                'created_date': created_date.isoformat() if created_date else '',
                                'last_accessed_date': last_accessed_date.isoformat() if last_accessed_date else '',
                                'last_changed_date': last_changed_date.isoformat() if last_changed_date else '',
                                'last_rotated_date': last_rotated_date.isoformat() if last_rotated_date else '',
                                'next_rotation_date': next_rotation_date.isoformat() if next_rotation_date else '',
                                'kms_key_id': kms_key_id,
                                'replica_regions_count': len(replica_regions),
                                'description': secret_details.get('Description', ''),
                                'tags': secret_details.get('Tags', [])
                            }
                        }
                    else:
                        # Non-compliant: Automatic rotation is not enabled
                        finding = {
                            'region': region,
                            'profile': profile,
                            'resource_type': 'Secrets Manager Secret',
                            'resource_id': secret_name,
                            'status': 'NON_COMPLIANT',
                            'compliance_status': 'FAIL',
                            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable automatic rotation for this secret'),
                            'details': {
                                'secret_name': secret_name,
                                'secret_arn': secret_arn,
                                'rotation_enabled': rotation_enabled,
                                'issue': 'Automatic rotation is not enabled for this secret',
                                'created_date': created_date.isoformat() if created_date else '',
                                'last_accessed_date': last_accessed_date.isoformat() if last_accessed_date else '',
                                'last_changed_date': last_changed_date.isoformat() if last_changed_date else '',
                                'kms_key_id': kms_key_id,
                                'replica_regions_count': len(replica_regions),
                                'security_risk': 'Secrets without automatic rotation may become compromised over time',
                                'remediation_steps': [
                                    'Configure Lambda function for automatic rotation',
                                    'Set up rotation rules with appropriate interval',
                                    'Test rotation functionality',
                                    'Monitor rotation status and failures',
                                    'Ensure applications can handle rotated credentials'
                                ],
                                'description': secret_details.get('Description', ''),
                                'tags': secret_details.get('Tags', [])
                            }
                        }
                    
                    findings.append(finding)
                    
                except Exception as e:
                    logger.error(f"Error checking secret {secret_name} in {region}: {e}")
                    findings.append({
                        'region': region,
                        'profile': profile,
                        'resource_type': 'Secrets Manager Secret',
                        'resource_id': secret_name,
                        'status': 'ERROR',
                        'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                        'recommendation': COMPLIANCE_DATA.get('recommendation', 'Review secret configuration'),
                        'error': str(e)
                    })
        
        if not findings:
            logger.info(f"No Secrets Manager secrets found in region {region}")
        
    except Exception as e:
        logger.error(f"Error in secretsmanager_automatic_rotation_enabled check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'Secrets Manager Secret',
            'status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Review and remediate as needed'),
            'error': str(e)
        })
        
    return findings

def secretsmanager_automatic_rotation_enabled(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=secretsmanager_automatic_rotation_enabled_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = secretsmanager_automatic_rotation_enabled(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

#!/usr/bin/env python3
"""
aws_foundational_security_best_practices_aws - backup_recovery_point_encrypted

Recovery points should be encrypted
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
    """Load compliance metadata from compliance_checks.json."""
    try:
        compliance_json_path = os.path.join(
            os.path.dirname(__file__), '..', '..', 'compliance_checks.json'
        )
        
        with open(compliance_json_path, 'r') as f:
            compliance_data = json.load(f)
        
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
        
    return {
        'compliance_name': 'aws_foundational_security_best_practices_aws',
        'function_name': 'backup_recovery_point_encrypted',
        'id': 'Backup.1',
        'name': 'Recovery points should be encrypted',
        'description': 'Recovery points should be encrypted',
        'api_function': 'client = boto3.client(\'backup\')',
        'user_function': 'list_recovery_points_by_backup_vault(), describe_recovery_point()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Ensure backup recovery points are encrypted'
    }

COMPLIANCE_DATA = load_compliance_metadata('backup_recovery_point_encrypted')

def backup_recovery_point_encrypted_check(backup_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for backup_recovery_point_encrypted.
    """
    findings = []
    
    try:
        # Get all backup vaults
        vaults_response = backup_client.list_backup_vaults()
        backup_vaults = vaults_response.get('BackupVaultList', [])
        
        if not backup_vaults:
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'Backup Recovery Point',
                'resource_id': f'no-vaults-{region}',
                'status': 'COMPLIANT',
                'compliance_status': 'PASS',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                'recommendation': COMPLIANCE_DATA.get('recommendation', 'Ensure backup recovery points are encrypted'),
                'details': {
                    'message': 'No backup vaults found in this region',
                    'vault_count': 0
                }
            }
            findings.append(finding)
            return findings
        
        total_recovery_points = 0
        
        # Check recovery points in each vault
        for vault in backup_vaults:
            vault_name = vault.get('BackupVaultName')
            vault_arn = vault.get('BackupVaultArn')
            
            try:
                # Get recovery points for this vault
                paginator = backup_client.get_paginator('list_recovery_points_by_backup_vault')
                
                for page in paginator.paginate(BackupVaultName=vault_name):
                    recovery_points = page.get('RecoveryPoints', [])
                    total_recovery_points += len(recovery_points)
                    
                    for recovery_point in recovery_points:
                        recovery_point_arn = recovery_point.get('RecoveryPointArn')
                        backup_vault_name = recovery_point.get('BackupVaultName')
                        encryption_key_arn = recovery_point.get('EncryptionKeyArn')
                        is_encrypted = recovery_point.get('IsEncrypted', False)
                        
                        # Check encryption status
                        if is_encrypted and encryption_key_arn:
                            status = 'COMPLIANT'
                            compliance_status = 'PASS'
                            message = f'Recovery point {recovery_point_arn} is encrypted'
                        else:
                            status = 'NON_COMPLIANT'
                            compliance_status = 'FAIL'
                            message = f'Recovery point {recovery_point_arn} is not encrypted'
                        
                        finding = {
                            'region': region,
                            'profile': profile,
                            'resource_type': 'Backup Recovery Point',
                            'resource_id': recovery_point_arn,
                            'status': status,
                            'compliance_status': compliance_status,
                            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Ensure backup recovery points are encrypted'),
                            'details': {
                                'recovery_point_arn': recovery_point_arn,
                                'backup_vault_name': backup_vault_name,
                                'is_encrypted': is_encrypted,
                                'encryption_key_arn': encryption_key_arn,
                                'resource_arn': recovery_point.get('ResourceArn'),
                                'resource_type': recovery_point.get('ResourceType'),
                                'creation_date': recovery_point.get('CreationDate'),
                                'status': recovery_point.get('Status'),
                                'message': message
                            }
                        }
                        findings.append(finding)
                        
            except Exception as e:
                logger.error(f"Error checking recovery points for vault {vault_name}: {e}")
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'Backup Vault',
                    'resource_id': vault_arn,
                    'status': 'ERROR',
                    'compliance_status': 'ERROR',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Ensure backup recovery points are encrypted'),
                    'error': str(e),
                    'details': {
                        'vault_name': vault_name,
                        'vault_arn': vault_arn,
                        'message': f'Error checking recovery points for vault {vault_name}'
                    }
                }
                findings.append(finding)
        
        # If no recovery points found across all vaults
        if total_recovery_points == 0 and len(backup_vaults) > 0:
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'Backup Recovery Point',
                'resource_id': f'no-recovery-points-{region}',
                'status': 'COMPLIANT',
                'compliance_status': 'PASS',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                'recommendation': COMPLIANCE_DATA.get('recommendation', 'Ensure backup recovery points are encrypted'),
                'details': {
                    'message': f'No recovery points found across {len(backup_vaults)} backup vault(s)',
                    'vault_count': len(backup_vaults),
                    'recovery_point_count': 0
                }
            }
            findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in backup_recovery_point_encrypted check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'Backup Recovery Point',
            'resource_id': f'error-{region}',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Ensure backup recovery points are encrypted'),
            'error': str(e)
        })
        
    return findings

def backup_recovery_point_encrypted(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=backup_recovery_point_encrypted_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    args = setup_command_line_interface(COMPLIANCE_DATA)
    results = backup_recovery_point_encrypted(
        profile_name=args.profile,
        region_name=args.region
    )
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

#!/usr/bin/env python3
"""
iso27001_2022_aws - backup_vaults_encrypted

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
                    'risk_level': entry.get('Risk Level', 'MEDIUM'),
                    'recommendation': entry.get('Recommendation', 'Enable encryption for all backup vaults')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'iso27001_2022_aws',
        'function_name': 'backup_vaults_encrypted',
        'id': 'ISO27001-2022-AWS-BACKUP-VAULT-ENC',
        'name': 'Backup Vaults Encrypted',
        'description': 'Rules for the effective use of cryptography, including cryptographic key management, should be defined and implemented.',
        'api_function': 'client = boto3.client(\'backup\')',
        'user_function': 'list_backup_vaults(), describe_backup_vault()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Enable encryption for all backup vaults'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('backup_vaults_encrypted')

def backup_vaults_encrypted_check(backup_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Check if AWS Backup vaults are encrypted.
    
    Args:
        backup_client: Boto3 Backup client
        region (str): AWS region
        profile (str): AWS profile name
        logger: Logger instance
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    try:
        # List all backup vaults
        response = backup_client.list_backup_vaults()
        backup_vaults = response.get('BackupVaultList', [])
        
        if not backup_vaults:
            # No backup vaults found - compliant (nothing to check)
            findings.append({
                'region': region,
                'profile': profile,
                'resource_type': 'AWS Backup Vaults',
                'resource_id': f'backup-vaults-{region}',
                'status': 'COMPLIANT',
                'compliance_status': 'PASS',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                'recommendation': 'No backup vaults found - create encrypted backup vaults when needed',
                'details': {
                    'vault_count': 0,
                    'reason': 'No backup vaults to evaluate'
                }
            })
        else:
            # Analyze each backup vault for encryption
            for vault in backup_vaults:
                vault_name = vault.get('BackupVaultName', 'Unknown')
                vault_arn = vault.get('BackupVaultArn', '')
                encryption_key_arn = vault.get('EncryptionKeyArn')
                creation_date = vault.get('CreationDate')
                
                try:
                    # Get detailed vault information
                    vault_details = backup_client.describe_backup_vault(BackupVaultName=vault_name)
                    
                    # Check encryption status
                    encryption_key_arn = vault_details.get('EncryptionKeyArn') or encryption_key_arn
                    
                    if encryption_key_arn:
                        # Vault is encrypted - compliant
                        findings.append({
                            'region': region,
                            'profile': profile,
                            'resource_type': 'AWS Backup Vault',
                            'resource_id': vault_name,
                            'status': 'COMPLIANT',
                            'compliance_status': 'PASS',
                            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                            'recommendation': 'Backup vault is properly encrypted',
                            'details': {
                                'vault_name': vault_name,
                                'vault_arn': vault_arn,
                                'creation_date': creation_date.isoformat() if creation_date else 'Unknown',
                                'encryption_key_arn': encryption_key_arn,
                                'encryption_status': 'Enabled'
                            }
                        })
                    else:
                        # Vault is not encrypted - non-compliant
                        findings.append({
                            'region': region,
                            'profile': profile,
                            'resource_type': 'AWS Backup Vault',
                            'resource_id': vault_name,
                            'status': 'NON_COMPLIANT',
                            'compliance_status': 'FAIL',
                            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable encryption for all backup vaults'),
                            'details': {
                                'vault_name': vault_name,
                                'vault_arn': vault_arn,
                                'creation_date': creation_date.isoformat() if creation_date else 'Unknown',
                                'encryption_key_arn': 'Not configured',
                                'encryption_status': 'Disabled',
                                'issue': 'Backup vault is not encrypted'
                            }
                        })
                        
                except Exception as e:
                    logger.warning(f"Error getting details for backup vault {vault_name}: {e}")
                    findings.append({
                        'region': region,
                        'profile': profile,
                        'resource_type': 'AWS Backup Vault',
                        'resource_id': vault_name,
                        'status': 'ERROR',
                        'compliance_status': 'ERROR',
                        'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                        'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable encryption for all backup vaults'),
                        'details': {
                            'vault_name': vault_name,
                            'vault_arn': vault_arn,
                            'error': f'Error getting vault details: {str(e)}'
                        }
                    })
            
            # Add summary finding
            compliant_vaults = sum(1 for finding in findings if finding.get('status') == 'COMPLIANT')
            
            findings.append({
                'region': region,
                'profile': profile,
                'resource_type': 'AWS Backup Vault Summary',
                'resource_id': f'backup-vault-encryption-summary-{region}',
                'status': 'COMPLIANT' if compliant_vaults == len(backup_vaults) else 'NON_COMPLIANT',
                'compliance_status': 'PASS' if compliant_vaults == len(backup_vaults) else 'FAIL',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                'recommendation': 'All backup vaults are encrypted' if compliant_vaults == len(backup_vaults) else COMPLIANCE_DATA.get('recommendation', 'Enable encryption for all backup vaults'),
                'details': {
                    'total_vaults': len(backup_vaults),
                    'encrypted_vaults': compliant_vaults,
                    'unencrypted_vaults': len(backup_vaults) - compliant_vaults,
                    'encryption_percentage': round((compliant_vaults / len(backup_vaults)) * 100, 2) if backup_vaults else 0
                }
            })
        
    except Exception as e:
        logger.error(f"Error in backup_vaults_encrypted check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'AWS Backup Vaults',
            'resource_id': f'backup-vault-encryption-check-{region}',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable encryption for all backup vaults'),
            'error': str(e)
        })
        
    return findings

def backup_vaults_encrypted(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=backup_vaults_encrypted_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = backup_vaults_encrypted(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

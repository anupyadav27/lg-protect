#!/usr/bin/env python3
"""
iso27001_2022_aws - backup_vaults_exist

Backup copies of information, software and systems should be maintained and regularly tested in accordance with the agreed topic-specific policy on backup.
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
                    'recommendation': entry.get('Recommendation', 'Create AWS Backup vaults for data protection')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'iso27001_2022_aws',
        'function_name': 'backup_vaults_exist',
        'id': 'ISO27001-2022-AWS-BACKUP-VAULTS',
        'name': 'Backup Vaults Exist',
        'description': 'Backup copies of information, software and systems should be maintained and regularly tested in accordance with the agreed topic-specific policy on backup.',
        'api_function': 'client = boto3.client(\'backup\')',
        'user_function': 'list_backup_vaults()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Create AWS Backup vaults for data protection'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('backup_vaults_exist')

def backup_vaults_exist_check(backup_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Check if AWS Backup vaults exist.
    
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
            # No backup vaults found - non-compliant
            findings.append({
                'region': region,
                'profile': profile,
                'resource_type': 'AWS Backup Vaults',
                'resource_id': f'backup-vaults-{region}',
                'status': 'NON_COMPLIANT',
                'compliance_status': 'FAIL',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                'recommendation': COMPLIANCE_DATA.get('recommendation', 'Create AWS Backup vaults for data protection'),
                'details': {
                    'vault_count': 0,
                    'issue': 'No AWS Backup vaults found in this region',
                    'remediation': 'Create backup vaults to store backup data securely'
                }
            })
        else:
            # Analyze each backup vault
            for vault in backup_vaults:
                vault_name = vault.get('BackupVaultName', 'Unknown')
                vault_arn = vault.get('BackupVaultArn', '')
                encryption_key_arn = vault.get('EncryptionKeyArn')
                creation_date = vault.get('CreationDate')
                
                # Vault exists - compliant
                findings.append({
                    'region': region,
                    'profile': profile,
                    'resource_type': 'AWS Backup Vault',
                    'resource_id': vault_name,
                    'status': 'COMPLIANT',
                    'compliance_status': 'PASS',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                    'recommendation': 'Backup vault exists and is available for data protection',
                    'details': {
                        'vault_name': vault_name,
                        'vault_arn': vault_arn,
                        'creation_date': creation_date.isoformat() if creation_date else 'Unknown',
                        'encryption_key_arn': encryption_key_arn or 'Default encryption',
                        'vault_status': 'Available'
                    }
                })
            
            # Add summary finding
            findings.append({
                'region': region,
                'profile': profile,
                'resource_type': 'AWS Backup Vault Summary',
                'resource_id': f'backup-vault-summary-{region}',
                'status': 'COMPLIANT',
                'compliance_status': 'PASS',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                'recommendation': 'AWS Backup vaults are configured for data protection',
                'details': {
                    'total_vaults': len(backup_vaults),
                    'vault_names': [vault.get('BackupVaultName', 'Unknown') for vault in backup_vaults[:5]],  # Limit to first 5
                    'vault_count_status': f'{len(backup_vaults)} backup vaults found'
                }
            })
        
    except Exception as e:
        logger.error(f"Error in backup_vaults_exist check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'AWS Backup Vaults',
            'resource_id': f'backup-vault-check-{region}',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Create AWS Backup vaults for data protection'),
            'error': str(e)
        })
        
    return findings

def backup_vaults_exist(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=backup_vaults_exist_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = backup_vaults_exist(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

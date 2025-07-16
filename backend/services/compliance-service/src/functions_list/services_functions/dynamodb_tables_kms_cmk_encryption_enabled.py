#!/usr/bin/env python3
"""
aws_compliance_framework - dynamodb_tables_kms_cmk_encryption_enabled

Ensure DynamoDB tables use customer-managed KMS keys for encryption at rest to provide better control over encryption keys.
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
                    'recommendation': entry.get('Recommendation', 'Configure DynamoDB tables to use customer-managed KMS keys')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'aws_compliance_framework',
        'function_name': 'dynamodb_tables_kms_cmk_encryption_enabled',
        'id': 'DDB-KMS-001',
        'name': 'DynamoDB Tables KMS CMK Encryption',
        'description': 'Ensure DynamoDB tables use customer-managed KMS keys for encryption at rest to provide better control over encryption keys.',
        'api_function': 'client = boto3.client(\'dynamodb\')',
        'user_function': 'list_tables(), describe_table()',
        'risk_level': 'HIGH',
        'recommendation': 'Configure DynamoDB tables to use customer-managed KMS keys instead of AWS managed keys for better security control'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('dynamodb_tables_kms_cmk_encryption_enabled')

def dynamodb_tables_kms_cmk_encryption_enabled_check(dynamodb_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for DynamoDB tables KMS CMK encryption.
    
    Args:
        dynamodb_client: Boto3 DynamoDB client (auto-created by framework)
        region (str): AWS region (auto-managed by framework)
        profile (str): AWS profile name (auto-managed by framework)
        logger: Logger instance (auto-configured by framework)
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    try:
        # Get all DynamoDB tables in the region
        response = dynamodb_client.list_tables()
        table_names = response.get('TableNames', [])
        
        if not table_names:
            # No tables found - compliant by default
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'DynamoDB',
                'resource_id': f'no-tables-{region}',
                'status': 'COMPLIANT',
                'compliance_status': 'PASS',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                'recommendation': 'No DynamoDB tables found in this region',
                'details': {
                    'total_tables': 0,
                    'cmk_encrypted_tables': 0,
                    'aws_managed_encrypted_tables': 0
                }
            }
            findings.append(finding)
            return findings
        
        cmk_encrypted_tables = []
        non_cmk_encrypted_tables = []
        
        # Check encryption settings for each table
        for table_name in table_names:
            try:
                table_response = dynamodb_client.describe_table(
                    TableName=table_name
                )
                
                table_description = table_response.get('Table', {})
                sse_description = table_description.get('SSEDescription', {})
                
                encryption_type = sse_description.get('SSEType', 'NONE')
                kms_master_key_id = sse_description.get('KMSMasterKeyId')
                encryption_status = sse_description.get('Status', 'DISABLED')
                
                table_info = {
                    'table_name': table_name,
                    'encryption_type': encryption_type,
                    'kms_master_key_id': kms_master_key_id,
                    'encryption_status': encryption_status,
                    'table_status': table_description.get('TableStatus', 'UNKNOWN')
                }
                
                # Check if using customer-managed KMS key
                # KMS type means customer-managed key, AES256 means AWS managed
                if encryption_type == 'KMS' and kms_master_key_id:
                    # Additional check to ensure it's not the default AWS managed key
                    if not kms_master_key_id.startswith('alias/aws/dynamodb'):
                        cmk_encrypted_tables.append(table_info)
                    else:
                        table_info['issue'] = 'Using AWS managed key instead of customer-managed key'
                        non_cmk_encrypted_tables.append(table_info)
                else:
                    table_info['issue'] = f'Encryption type: {encryption_type}, not using customer-managed KMS key'
                    non_cmk_encrypted_tables.append(table_info)
                    
            except Exception as e:
                logger.warning(f"Error checking encryption for table {table_name}: {e}")
                non_cmk_encrypted_tables.append({
                    'table_name': table_name,
                    'encryption_type': 'UNKNOWN',
                    'error': str(e),
                    'issue': 'Could not determine encryption status'
                })
        
        # Create findings for non-compliant tables
        for table_info in non_cmk_encrypted_tables:
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'DynamoDB Table',
                'resource_id': table_info['table_name'],
                'status': 'NON_COMPLIANT',
                'compliance_status': 'FAIL',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                'recommendation': COMPLIANCE_DATA.get('recommendation', 'Configure DynamoDB tables to use customer-managed KMS keys'),
                'details': {
                    'table_name': table_info['table_name'],
                    'encryption_type': table_info.get('encryption_type', 'UNKNOWN'),
                    'kms_master_key_id': table_info.get('kms_master_key_id'),
                    'encryption_status': table_info.get('encryption_status'),
                    'issue': table_info.get('issue', 'Not using customer-managed KMS key'),
                    'impact': 'Reduced control over encryption keys and key rotation policies'
                }
            }
            findings.append(finding)
        
        # Create findings for compliant tables
        for table_info in cmk_encrypted_tables:
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'DynamoDB Table',
                'resource_id': table_info['table_name'],
                'status': 'COMPLIANT',
                'compliance_status': 'PASS',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                'recommendation': 'Customer-managed KMS key encryption is properly configured',
                'details': {
                    'table_name': table_info['table_name'],
                    'encryption_type': table_info['encryption_type'],
                    'kms_master_key_id': table_info.get('kms_master_key_id'),
                    'encryption_status': table_info.get('encryption_status')
                }
            }
            findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in dynamodb_tables_kms_cmk_encryption_enabled check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'DynamoDB',
            'resource_id': f'check-error-{region}',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Configure DynamoDB tables to use customer-managed KMS keys'),
            'error': str(e)
        })
        
    return findings

def dynamodb_tables_kms_cmk_encryption_enabled(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=dynamodb_tables_kms_cmk_encryption_enabled_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = dynamodb_tables_kms_cmk_encryption_enabled(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

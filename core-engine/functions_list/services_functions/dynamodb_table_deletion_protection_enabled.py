#!/usr/bin/env python3
"""
aws_compliance_framework - dynamodb_table_deletion_protection_enabled

Ensure DynamoDB tables have deletion protection enabled to prevent accidental data loss.
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
                    'recommendation': entry.get('Recommendation', 'Enable deletion protection for all DynamoDB tables')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'aws_compliance_framework',
        'function_name': 'dynamodb_table_deletion_protection_enabled',
        'id': 'DDB-DEL-001',
        'name': 'DynamoDB Table Deletion Protection',
        'description': 'Ensure DynamoDB tables have deletion protection enabled to prevent accidental data loss.',
        'api_function': 'client = boto3.client(\'dynamodb\')',
        'user_function': 'list_tables(), describe_table()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Enable deletion protection for all DynamoDB tables to prevent accidental deletion'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('dynamodb_table_deletion_protection_enabled')

def dynamodb_table_deletion_protection_enabled_check(dynamodb_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for DynamoDB table deletion protection.
    
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
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                'recommendation': 'No DynamoDB tables found in this region',
                'details': {
                    'total_tables': 0,
                    'protected_tables': 0,
                    'unprotected_tables': 0
                }
            }
            findings.append(finding)
            return findings
        
        protected_tables = []
        unprotected_tables = []
        
        # Check deletion protection status for each table
        for table_name in table_names:
            try:
                table_response = dynamodb_client.describe_table(
                    TableName=table_name
                )
                
                table_description = table_response.get('Table', {})
                deletion_protection_enabled = table_description.get('DeletionProtectionEnabled', False)
                
                table_info = {
                    'table_name': table_name,
                    'deletion_protection_enabled': deletion_protection_enabled,
                    'table_status': table_description.get('TableStatus', 'UNKNOWN'),
                    'creation_date': table_description.get('CreationDateTime'),
                    'table_arn': table_description.get('TableArn', '')
                }
                
                if deletion_protection_enabled:
                    protected_tables.append(table_info)
                else:
                    table_info['issue'] = 'Deletion protection is not enabled'
                    unprotected_tables.append(table_info)
                    
            except Exception as e:
                logger.warning(f"Error checking deletion protection for table {table_name}: {e}")
                unprotected_tables.append({
                    'table_name': table_name,
                    'deletion_protection_enabled': False,
                    'error': str(e),
                    'issue': 'Could not determine deletion protection status'
                })
        
        # Create findings for unprotected tables
        for table_info in unprotected_tables:
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'DynamoDB Table',
                'resource_id': table_info['table_name'],
                'status': 'NON_COMPLIANT',
                'compliance_status': 'FAIL',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable deletion protection for all DynamoDB tables'),
                'details': {
                    'table_name': table_info['table_name'],
                    'deletion_protection_enabled': table_info.get('deletion_protection_enabled', False),
                    'issue': table_info.get('issue', 'Deletion protection not enabled'),
                    'impact': 'Table can be accidentally deleted without additional confirmation',
                    'table_status': table_info.get('table_status')
                }
            }
            findings.append(finding)
        
        # Create findings for protected tables
        for table_info in protected_tables:
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'DynamoDB Table',
                'resource_id': table_info['table_name'],
                'status': 'COMPLIANT',
                'compliance_status': 'PASS',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                'recommendation': 'Deletion protection is properly enabled',
                'details': {
                    'table_name': table_info['table_name'],
                    'deletion_protection_enabled': table_info['deletion_protection_enabled'],
                    'table_status': table_info.get('table_status'),
                    'creation_date': table_info.get('creation_date')
                }
            }
            findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in dynamodb_table_deletion_protection_enabled check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'DynamoDB',
            'resource_id': f'check-error-{region}',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable deletion protection for all DynamoDB tables'),
            'error': str(e)
        })
        
    return findings

def dynamodb_table_deletion_protection_enabled(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=dynamodb_table_deletion_protection_enabled_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = dynamodb_table_deletion_protection_enabled(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

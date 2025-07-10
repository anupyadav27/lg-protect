#!/usr/bin/env python3
"""
aws_compliance_framework - dynamodb_tables_pitr_enabled

Ensure DynamoDB tables have Point-in-Time Recovery (PITR) enabled for data protection and recovery capabilities.
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
                    'recommendation': entry.get('Recommendation', 'Enable Point-in-Time Recovery (PITR) for all DynamoDB tables')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'aws_compliance_framework',
        'function_name': 'dynamodb_tables_pitr_enabled',
        'id': 'DDB-PITR-001',
        'name': 'DynamoDB Tables PITR Enabled',
        'description': 'Ensure DynamoDB tables have Point-in-Time Recovery (PITR) enabled for data protection and recovery capabilities.',
        'api_function': 'client = boto3.client(\'dynamodb\')',
        'user_function': 'list_tables(), describe_continuous_backups()',
        'risk_level': 'HIGH',
        'recommendation': 'Enable Point-in-Time Recovery (PITR) for all DynamoDB tables to ensure data can be recovered to any point within the last 35 days'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('dynamodb_tables_pitr_enabled')

def dynamodb_tables_pitr_enabled_check(dynamodb_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for DynamoDB tables PITR enabled.
    
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
                    'pitr_enabled_tables': 0,
                    'pitr_disabled_tables': 0
                }
            }
            findings.append(finding)
            return findings
        
        pitr_enabled_tables = []
        pitr_disabled_tables = []
        
        # Check PITR status for each table
        for table_name in table_names:
            try:
                backup_response = dynamodb_client.describe_continuous_backups(
                    TableName=table_name
                )
                
                continuous_backups = backup_response.get('ContinuousBackupsDescription', {})
                pitr_description = continuous_backups.get('PointInTimeRecoveryDescription', {})
                pitr_status = pitr_description.get('PointInTimeRecoveryStatus', 'DISABLED')
                
                table_info = {
                    'table_name': table_name,
                    'pitr_status': pitr_status,
                    'earliest_restorable_datetime': pitr_description.get('EarliestRestorableDateTime'),
                    'latest_restorable_datetime': pitr_description.get('LatestRestorableDateTime')
                }
                
                if pitr_status == 'ENABLED':
                    pitr_enabled_tables.append(table_info)
                else:
                    pitr_disabled_tables.append(table_info)
                    
            except Exception as e:
                logger.warning(f"Error checking PITR status for table {table_name}: {e}")
                pitr_disabled_tables.append({
                    'table_name': table_name,
                    'pitr_status': 'UNKNOWN',
                    'error': str(e)
                })
        
        # Create findings based on results
        for table_info in pitr_disabled_tables:
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'DynamoDB Table',
                'resource_id': table_info['table_name'],
                'status': 'NON_COMPLIANT',
                'compliance_status': 'FAIL',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable Point-in-Time Recovery (PITR) for all DynamoDB tables'),
                'details': {
                    'table_name': table_info['table_name'],
                    'pitr_status': table_info.get('pitr_status', 'DISABLED'),
                    'issue': 'Point-in-Time Recovery is not enabled',
                    'impact': 'Data cannot be recovered to specific points in time without PITR'
                }
            }
            findings.append(finding)
        
        for table_info in pitr_enabled_tables:
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'DynamoDB Table',
                'resource_id': table_info['table_name'],
                'status': 'COMPLIANT',
                'compliance_status': 'PASS',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                'recommendation': 'Point-in-Time Recovery is properly enabled',
                'details': {
                    'table_name': table_info['table_name'],
                    'pitr_status': table_info['pitr_status'],
                    'earliest_restorable_datetime': table_info.get('earliest_restorable_datetime'),
                    'latest_restorable_datetime': table_info.get('latest_restorable_datetime')
                }
            }
            findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in dynamodb_tables_pitr_enabled check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'DynamoDB',
            'resource_id': f'check-error-{region}',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable Point-in-Time Recovery (PITR) for all DynamoDB tables'),
            'error': str(e)
        })
        
    return findings

def dynamodb_tables_pitr_enabled(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=dynamodb_tables_pitr_enabled_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = dynamodb_tables_pitr_enabled(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

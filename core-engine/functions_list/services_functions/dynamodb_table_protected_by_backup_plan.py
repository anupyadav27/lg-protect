#!/usr/bin/env python3
"""
aws_compliance_framework - dynamodb_table_protected_by_backup_plan

Ensure DynamoDB tables are protected by AWS Backup plans for comprehensive data protection and disaster recovery.
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
                    'recommendation': entry.get('Recommendation', 'Include DynamoDB tables in AWS Backup plans')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'aws_compliance_framework',
        'function_name': 'dynamodb_table_protected_by_backup_plan',
        'id': 'DDB-BACKUP-001',
        'name': 'DynamoDB Table Backup Protection',
        'description': 'Ensure DynamoDB tables are protected by AWS Backup plans for comprehensive data protection and disaster recovery.',
        'api_function': 'client = boto3.client(\'backup\')',
        'user_function': 'list_protected_resources(), describe_protected_resource()',
        'risk_level': 'HIGH',
        'recommendation': 'Include DynamoDB tables in AWS Backup plans to ensure comprehensive backup coverage and disaster recovery capabilities'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('dynamodb_table_protected_by_backup_plan')

def dynamodb_table_protected_by_backup_plan_check(backup_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for DynamoDB tables backup protection.
    
    Args:
        backup_client: Boto3 Backup client (auto-created by framework)
        region (str): AWS region (auto-managed by framework)
        profile (str): AWS profile name (auto-managed by framework)
        logger: Logger instance (auto-configured by framework)
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    try:
        # Import boto3 to create DynamoDB client for listing tables
        import boto3
        
        # Create session with the same profile
        if profile != 'default':
            session = boto3.Session(profile_name=profile)
            dynamodb_client = session.client('dynamodb', region_name=region)
        else:
            dynamodb_client = boto3.client('dynamodb', region_name=region)
        
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
                    'protected_tables': 0,
                    'unprotected_tables': 0
                }
            }
            findings.append(finding)
            return findings
        
        # Get protected resources from AWS Backup
        protected_resources = set()
        try:
            paginator = backup_client.get_paginator('list_protected_resources')
            for page in paginator.paginate():
                for resource in page.get('Results', []):
                    resource_type = resource.get('ResourceType')
                    resource_arn = resource.get('ResourceArn', '')
                    
                    # Check if it's a DynamoDB table
                    if resource_type == 'DynamoDB' and resource_arn:
                        # Extract table name from ARN
                        # DynamoDB ARN format: arn:aws:dynamodb:region:account:table/table-name
                        table_name = resource_arn.split('/')[-1] if '/' in resource_arn else resource_arn
                        protected_resources.add(table_name)
                        
        except Exception as e:
            logger.warning(f"Error retrieving protected resources: {e}")
        
        protected_tables = []
        unprotected_tables = []
        
        # Check each table's backup protection status
        for table_name in table_names:
            if table_name in protected_resources:
                # Get more details about the protection
                try:
                    table_arn = f"arn:aws:dynamodb:{region}:*:table/{table_name}"
                    protection_response = backup_client.describe_protected_resource(
                        ResourceArn=table_arn
                    )
                    
                    table_info = {
                        'table_name': table_name,
                        'protected': True,
                        'last_backup_time': protection_response.get('LastBackupTime'),
                        'last_recovery_point_time': protection_response.get('LastRecoveryPointTime')
                    }
                    protected_tables.append(table_info)
                    
                except Exception as e:
                    # Table is in protected list but can't get details
                    table_info = {
                        'table_name': table_name,
                        'protected': True,
                        'note': 'Protected but details unavailable'
                    }
                    protected_tables.append(table_info)
            else:
                table_info = {
                    'table_name': table_name,
                    'protected': False,
                    'issue': 'Table not included in any AWS Backup plan'
                }
                unprotected_tables.append(table_info)
        
        # Create findings for unprotected tables
        for table_info in unprotected_tables:
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'DynamoDB Table',
                'resource_id': table_info['table_name'],
                'status': 'NON_COMPLIANT',
                'compliance_status': 'FAIL',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                'recommendation': COMPLIANCE_DATA.get('recommendation', 'Include DynamoDB tables in AWS Backup plans'),
                'details': {
                    'table_name': table_info['table_name'],
                    'protected': table_info['protected'],
                    'issue': table_info.get('issue', 'Not protected by backup plan'),
                    'impact': 'No automated backup coverage for disaster recovery'
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
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                'recommendation': 'Table is properly protected by AWS Backup plan',
                'details': {
                    'table_name': table_info['table_name'],
                    'protected': table_info['protected'],
                    'last_backup_time': table_info.get('last_backup_time'),
                    'last_recovery_point_time': table_info.get('last_recovery_point_time')
                }
            }
            findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in dynamodb_table_protected_by_backup_plan check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'DynamoDB',
            'resource_id': f'check-error-{region}',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Include DynamoDB tables in AWS Backup plans'),
            'error': str(e)
        })
        
    return findings

def dynamodb_table_protected_by_backup_plan(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=dynamodb_table_protected_by_backup_plan_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = dynamodb_table_protected_by_backup_plan(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

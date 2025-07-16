#!/usr/bin/env python3
"""
fedramp_low_revision_4_aws - cloudwatch_log_group_kms_encryption_enabled

The information system protects audit information and audit tools from unauthorized access, modification, and deletion.
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
        'compliance_name': 'fedramp_low_revision_4_aws',
        'function_name': 'cloudwatch_log_group_kms_encryption_enabled',
        'id': 'AU-9',
        'name': 'CloudWatch log groups should be encrypted with KMS',
        'description': 'The information system protects audit information and audit tools from unauthorized access, modification, and deletion',
        'api_function': 'client = boto3.client("logs")',
        'user_function': 'describe_log_groups()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Enable KMS encryption for CloudWatch log groups to protect log data'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('cloudwatch_log_group_kms_encryption_enabled')

def cloudwatch_log_group_kms_encryption_enabled_check(logs_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for cloudwatch_log_group_kms_encryption_enabled.
    
    Args:
        logs_client: Boto3 CloudWatch Logs client (auto-created by framework)
        region (str): AWS region (auto-managed by framework)
        profile (str): AWS profile name (auto-managed by framework)
        logger: Logger instance (auto-configured by framework)
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    try:
        logger.info(f"Checking CloudWatch log groups KMS encryption in region {region}")
        
        # Get all log groups using paginator
        paginator = logs_client.get_paginator('describe_log_groups')
        
        for page in paginator.paginate():
            log_groups = page.get('logGroups', [])
            
            if not log_groups:
                continue
            
            # Check each log group for KMS encryption
            for log_group in log_groups:
                log_group_name = log_group.get('logGroupName', 'unknown')
                creation_time = log_group.get('creationTime', 0)
                retention_in_days = log_group.get('retentionInDays', None)
                stored_bytes = log_group.get('storedBytes', 0)
                kms_key_id = log_group.get('kmsKeyId', None)
                
                # Convert creation time to readable format
                import datetime
                creation_date = datetime.datetime.fromtimestamp(creation_time / 1000).isoformat() if creation_time else ''
                
                if kms_key_id:
                    # Compliant: Log group is encrypted with KMS
                    finding = {
                        'region': region,
                        'profile': profile,
                        'resource_type': 'CloudWatch Log Group',
                        'resource_id': log_group_name,
                        'status': 'COMPLIANT',
                        'compliance_status': 'PASS',
                        'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                        'recommendation': COMPLIANCE_DATA.get('recommendation', 'KMS encryption is properly enabled'),
                        'details': {
                            'log_group_name': log_group_name,
                            'kms_key_id': kms_key_id,
                            'creation_date': creation_date,
                            'retention_in_days': retention_in_days,
                            'stored_bytes': stored_bytes,
                            'has_retention_policy': retention_in_days is not None,
                            'tags': log_group.get('tags', {})
                        }
                    }
                else:
                    # Non-compliant: Log group is not encrypted with KMS
                    finding = {
                        'region': region,
                        'profile': profile,
                        'resource_type': 'CloudWatch Log Group',
                        'resource_id': log_group_name,
                        'status': 'NON_COMPLIANT',
                        'compliance_status': 'FAIL',
                        'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                        'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable KMS encryption for this log group'),
                        'details': {
                            'log_group_name': log_group_name,
                            'kms_key_id': None,
                            'issue': 'Log group is not encrypted with KMS customer-managed key',
                            'creation_date': creation_date,
                            'retention_in_days': retention_in_days,
                            'stored_bytes': stored_bytes,
                            'has_retention_policy': retention_in_days is not None,
                            'security_risk': 'Log data is encrypted with AWS managed keys instead of customer-managed KMS keys, reducing control over encryption',
                            'remediation_steps': [
                                'Create or identify a KMS customer-managed key for CloudWatch Logs',
                                'Update the log group to use KMS encryption',
                                'Note: Existing log data will remain encrypted with previous method',
                                'New log data will be encrypted with the specified KMS key',
                                'Ensure proper IAM permissions for CloudWatch Logs to use the KMS key',
                                'Consider setting up log retention policies if not already configured'
                            ],
                            'tags': log_group.get('tags', {})
                        }
                    }
                
                findings.append(finding)
        
        if not findings:
            logger.info(f"No CloudWatch log groups found in region {region}")
        
    except Exception as e:
        logger.error(f"Error in cloudwatch_log_group_kms_encryption_enabled check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'CloudWatch Log Group',
            'status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Review and remediate as needed'),
            'error': str(e)
        })
        
    return findings

def cloudwatch_log_group_kms_encryption_enabled(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=cloudwatch_log_group_kms_encryption_enabled_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = cloudwatch_log_group_kms_encryption_enabled(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

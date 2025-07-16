#!/usr/bin/env python3
"""
fedramp_low_revision_4_aws - cloudwatch_log_group_retention_policy_specific_days_enabled

The organization retains audit records for at least 90 days to provide support for after-the-fact investigations of security incidents and to meet regulatory and organizational information retention requirements.
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
        'function_name': 'cloudwatch_log_group_retention_policy_specific_days_enabled',
        'id': 'AU-11',
        'name': 'Audit Record Retention',
        'description': 'The organization retains audit records for at least 90 days to provide support for after-the-fact investigations of security incidents and to meet regulatory and organizational information retention requirements.',
        'api_function': 'client = boto3.client(\'logs\')',
        'user_function': 'describe_log_groups()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Set retention policy of at least 90 days for CloudWatch log groups'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('cloudwatch_log_group_retention_policy_specific_days_enabled')

def cloudwatch_log_group_retention_policy_specific_days_enabled_check(logs_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for cloudwatch_log_group_retention_policy_specific_days_enabled.
    
    Args:
        logs_client: Boto3 CloudWatch Logs client (auto-created by framework)
        region (str): AWS region (auto-managed by framework)
        profile (str): AWS profile name (auto-managed by framework)
        logger: Logger instance (auto-configured by framework)
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    # Minimum retention period in days (90 days for FedRAMP Low)
    MINIMUM_RETENTION_DAYS = 90
    
    try:
        # Get all log groups
        log_groups = []
        paginator = logs_client.get_paginator('describe_log_groups')
        
        for page in paginator.paginate():
            log_groups.extend(page.get('logGroups', []))
        
        if not log_groups:
            # No log groups found - compliant by default
            findings.append({
                'region': region,
                'profile': profile,
                'resource_type': 'CloudWatch Logs',
                'resource_id': f'no-log-groups-{region}',
                'status': 'COMPLIANT',
                'compliance_status': 'PASS',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                'recommendation': 'No CloudWatch log groups found',
                'details': {
                    'log_group_count': 0,
                    'message': 'No CloudWatch log groups exist in this region'
                }
            })
            return findings
        
        for log_group in log_groups:
            log_group_name = log_group.get('logGroupName', '')
            retention_in_days = log_group.get('retentionInDays')
            creation_time = log_group.get('creationTime')
            stored_bytes = log_group.get('storedBytes', 0)
            
            # Check retention policy
            retention_compliant = False
            retention_status = 'No retention policy set'
            
            if retention_in_days is None:
                # No retention policy means logs are kept indefinitely
                retention_compliant = True
                retention_status = 'Indefinite retention (compliant)'
            elif retention_in_days >= MINIMUM_RETENTION_DAYS:
                retention_compliant = True
                retention_status = f'Retention set to {retention_in_days} days (compliant)'
            else:
                retention_compliant = False
                retention_status = f'Retention set to {retention_in_days} days (non-compliant - less than {MINIMUM_RETENTION_DAYS} days)'
            
            if retention_compliant:
                status = 'COMPLIANT'
                compliance_status = 'PASS'
                recommendation = 'Log group retention policy meets requirements'
            else:
                status = 'NON_COMPLIANT'
                compliance_status = 'FAIL'
                recommendation = COMPLIANCE_DATA.get('recommendation', f'Set retention policy to at least {MINIMUM_RETENTION_DAYS} days')
            
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'CloudWatch Log Group',
                'resource_id': log_group_name,
                'status': status,
                'compliance_status': compliance_status,
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                'recommendation': recommendation,
                'details': {
                    'log_group_name': log_group_name,
                    'retention_in_days': retention_in_days,
                    'retention_status': retention_status,
                    'minimum_required_days': MINIMUM_RETENTION_DAYS,
                    'creation_time': creation_time,
                    'stored_bytes': stored_bytes,
                    'size_mb': round(stored_bytes / (1024 * 1024), 2) if stored_bytes else 0
                }
            }
            
            findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in cloudwatch_log_group_retention_policy_specific_days_enabled check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'CloudWatch Logs',
            'resource_id': f'check-error-{region}',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Review and remediate as needed'),
            'error': str(e)
        })
        
    return findings

def cloudwatch_log_group_retention_policy_specific_days_enabled(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=cloudwatch_log_group_retention_policy_specific_days_enabled_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = cloudwatch_log_group_retention_policy_specific_days_enabled(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

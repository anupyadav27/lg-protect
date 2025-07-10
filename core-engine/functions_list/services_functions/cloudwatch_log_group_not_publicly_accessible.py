#!/usr/bin/env python3
"""
CloudWatch Log Groups Not Publicly Accessible

Ensures that CloudWatch log groups are not publicly accessible to prevent unauthorized access to sensitive log data.
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
        'compliance_name': 'CloudWatch Security',
        'function_name': 'cloudwatch_log_group_not_publicly_accessible',
        'id': 'CWL-001',
        'name': 'CloudWatch Log Groups Not Publicly Accessible',
        'description': 'Ensures that CloudWatch log groups are not publicly accessible',
        'api_function': 'client = boto3.client("logs")',
        'user_function': 'describe_resource_policies()',
        'risk_level': 'HIGH',
        'recommendation': 'Remove public access from CloudWatch log groups and implement proper access controls'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('cloudwatch_log_group_not_publicly_accessible')

def cloudwatch_log_group_not_publicly_accessible_check(logs_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for cloudwatch_log_group_not_publicly_accessible.
    
    Args:
        logs_client: Boto3 logs client (auto-created by framework)
        region (str): AWS region (auto-managed by framework)
        profile (str): AWS profile name (auto-managed by framework)
        logger: Logger instance (auto-configured by framework)
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    try:
        # Check for resource policies that might allow public access
        try:
            response = logs_client.describe_resource_policies()
            resource_policies = response.get('resourcePolicies', [])
        except Exception as e:
            logger.info(f"No resource policies found in {region} or access denied: {e}")
            resource_policies = []
        
        # Get all log groups
        try:
            paginator = logs_client.get_paginator('describe_log_groups')
            log_groups = []
            for page in paginator.paginate():
                log_groups.extend(page.get('logGroups', []))
        except Exception as e:
            logger.error(f"Error describing log groups in {region}: {e}")
            log_groups = []
        
        # If no log groups found, return empty findings
        if not log_groups:
            return findings
        
        # Check each resource policy for public access
        publicly_accessible_policies = []
        for policy in resource_policies:
            policy_document = policy.get('policyDocument', '{}')
            try:
                policy_json = json.loads(policy_document)
                statements = policy_json.get('Statement', [])
                
                for statement in statements:
                    if isinstance(statement, dict):
                        principal = statement.get('Principal', {})
                        # Check for wildcard principals that allow public access
                        if principal == '*' or (isinstance(principal, dict) and principal.get('AWS') == '*'):
                            publicly_accessible_policies.append({
                                'policyName': policy.get('policyName'),
                                'statement': statement
                            })
            except json.JSONDecodeError:
                logger.warning(f"Could not parse policy document for policy {policy.get('policyName')}")
        
        # Create findings for log groups
        if publicly_accessible_policies:
            # Log groups are potentially publicly accessible due to resource policies
            for log_group in log_groups:
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'CloudWatch Log Group',
                    'resource_id': log_group.get('logGroupName', 'Unknown'),
                    'status': 'NON_COMPLIANT',
                    'compliance_status': 'FAIL',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Remove public access from CloudWatch log groups'),
                    'details': {
                        'log_group_name': log_group.get('logGroupName'),
                        'log_group_arn': log_group.get('arn'),
                        'publicly_accessible_policies': [p['policyName'] for p in publicly_accessible_policies],
                        'creation_time': log_group.get('creationTime'),
                        'retention_in_days': log_group.get('retentionInDays')
                    }
                }
                findings.append(finding)
        else:
            # No public access policies found - log groups are compliant
            for log_group in log_groups:
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'CloudWatch Log Group',
                    'resource_id': log_group.get('logGroupName', 'Unknown'),
                    'status': 'COMPLIANT',
                    'compliance_status': 'PASS',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                    'recommendation': 'Log group access is properly restricted',
                    'details': {
                        'log_group_name': log_group.get('logGroupName'),
                        'log_group_arn': log_group.get('arn'),
                        'creation_time': log_group.get('creationTime'),
                        'retention_in_days': log_group.get('retentionInDays')
                    }
                }
                findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in cloudwatch_log_group_not_publicly_accessible check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'CloudWatch Log Group',
            'status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Review and remediate as needed'),
            'error': str(e)
        })
        
    return findings

def cloudwatch_log_group_not_publicly_accessible(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=cloudwatch_log_group_not_publicly_accessible_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = cloudwatch_log_group_not_publicly_accessible(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

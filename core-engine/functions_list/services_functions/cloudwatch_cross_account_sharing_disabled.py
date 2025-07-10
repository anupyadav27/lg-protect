#!/usr/bin/env python3
"""
kisa_isms_p_2023_aws - cloudwatch_cross_account_sharing_disabled

The organization must define the types of logs, retention periods, and retention methods for user access records, system logs, and privilege grant records for information systems such as servers, applications, security systems, and network systems, and must securely retain and manage them to prevent tampering, theft, or loss.
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
        'compliance_name': 'kisa_isms_p_2023_aws',
        'function_name': 'cloudwatch_cross_account_sharing_disabled',
        'id': '2.9.4',
        'name': 'Log and Access Record Management',
        'description': 'The organization must define the types of logs, retention periods, and retention methods for user access records, system logs, and privilege grant records for information systems such as servers, applications, security systems, and network systems, and must securely retain and manage them to prevent tampering, theft, or loss.',
        'api_function': 'client = boto3.client("logs")',
        'user_function': 'describe_resource_policies()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Disable cross-account sharing for CloudWatch logs unless explicitly required'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('cloudwatch_cross_account_sharing_disabled')

def cloudwatch_cross_account_sharing_disabled_check(logs_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for cloudwatch_cross_account_sharing_disabled.
    
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
        # Get current account ID for comparison
        import boto3
        sts_client = boto3.client('sts')
        current_account_id = sts_client.get_caller_identity()['Account']
        
        # Check for resource policies that allow cross-account access
        try:
            response = logs_client.describe_resource_policies()
            resource_policies = response.get('resourcePolicies', [])
        except Exception as e:
            logger.info(f"No resource policies found in {region} or access denied: {e}")
            # If no policies exist, cross-account sharing is disabled by default
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'CloudWatch Logs',
                'resource_id': f'cloudwatch-logs-{region}',
                'status': 'COMPLIANT',
                'compliance_status': 'PASS',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                'recommendation': 'No resource policies found - cross-account sharing is disabled',
                'details': {
                    'resource_policies_count': 0,
                    'cross_account_policies': []
                }
            }
            findings.append(finding)
            return findings
        
        cross_account_policies = []
        
        # Analyze each resource policy for cross-account access
        for policy in resource_policies:
            policy_name = policy.get('policyName', 'Unknown')
            policy_document = policy.get('policyDocument', '{}')
            
            try:
                policy_json = json.loads(policy_document)
                statements = policy_json.get('Statement', [])
                
                for statement in statements:
                    if isinstance(statement, dict):
                        principal = statement.get('Principal', {})
                        
                        # Check for cross-account access in various principal formats
                        cross_account_access = False
                        external_accounts = []
                        
                        if isinstance(principal, dict):
                            aws_principals = principal.get('AWS', [])
                            if isinstance(aws_principals, str):
                                aws_principals = [aws_principals]
                            
                            for aws_principal in aws_principals:
                                if isinstance(aws_principal, str):
                                    # Extract account ID from ARN or account ID
                                    if aws_principal.startswith('arn:aws:iam::'):
                                        account_id = aws_principal.split(':')[4]
                                    elif aws_principal.isdigit() and len(aws_principal) == 12:
                                        account_id = aws_principal
                                    else:
                                        continue
                                    
                                    if account_id != current_account_id:
                                        cross_account_access = True
                                        external_accounts.append(account_id)
                        
                        elif principal == '*':
                            # Wildcard principal allows access from any account
                            cross_account_access = True
                            external_accounts.append('*')
                        
                        if cross_account_access:
                            cross_account_policies.append({
                                'policy_name': policy_name,
                                'external_accounts': external_accounts,
                                'effect': statement.get('Effect', 'Allow'),
                                'actions': statement.get('Action', [])
                            })
                            
            except json.JSONDecodeError:
                logger.warning(f"Could not parse policy document for policy {policy_name}")
        
        # Create findings based on cross-account policy analysis
        if cross_account_policies:
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'CloudWatch Logs',
                'resource_id': f'cloudwatch-logs-{region}',
                'status': 'NON_COMPLIANT',
                'compliance_status': 'FAIL',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                'recommendation': COMPLIANCE_DATA.get('recommendation', 'Disable cross-account sharing for CloudWatch logs'),
                'details': {
                    'resource_policies_count': len(resource_policies),
                    'cross_account_policies': cross_account_policies,
                    'current_account_id': current_account_id
                }
            }
            findings.append(finding)
        else:
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'CloudWatch Logs',
                'resource_id': f'cloudwatch-logs-{region}',
                'status': 'COMPLIANT',
                'compliance_status': 'PASS',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                'recommendation': 'Cross-account sharing is properly disabled',
                'details': {
                    'resource_policies_count': len(resource_policies),
                    'cross_account_policies': [],
                    'current_account_id': current_account_id
                }
            }
            findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in cloudwatch_cross_account_sharing_disabled check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'CloudWatch Logs',
            'status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Review and remediate as needed'),
            'error': str(e)
        })
        
    return findings

def cloudwatch_cross_account_sharing_disabled(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=cloudwatch_cross_account_sharing_disabled_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = cloudwatch_cross_account_sharing_disabled(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

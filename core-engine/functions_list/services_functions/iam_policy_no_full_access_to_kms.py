#!/usr/bin/env python3
"""
ens_rd2022_aws - iam_policy_no_full_access_to_kms

Protección de claves criptográficas
"""

import sys
import os
import json
import re
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
        'compliance_name': 'ens_rd2022_aws',
        'function_name': 'iam_policy_no_full_access_to_kms',
        'id': 'op.acc.5',
        'name': 'IAM policies should not grant full access to KMS',
        'description': 'Protección de claves criptográficas',
        'api_function': 'client = boto3.client("iam")',
        'user_function': 'list_users(), list_user_policies(), get_user_policy(), list_roles(), list_role_policies(), get_role_policy(), list_groups(), list_group_policies(), get_group_policy()',
        'risk_level': 'HIGH',
        'recommendation': 'Remove excessive KMS permissions from IAM policies and follow principle of least privilege'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('iam_policy_no_full_access_to_kms')

def check_policy_for_kms_full_access(policy_document: dict, policy_name: str, entity_type: str, entity_name: str) -> Dict[str, Any]:
    """
    Check a policy document for excessive KMS permissions.
    
    Returns:
        Dict containing policy analysis results
    """
    findings = []
    
    # Dangerous KMS permissions that grant excessive access
    dangerous_kms_actions = [
        'kms:*',
        'kms:CreateKey',
        'kms:CreateAlias',
        'kms:DeleteAlias',
        'kms:PutKeyPolicy',
        'kms:ScheduleKeyDeletion',
        'kms:CancelKeyDeletion',
        'kms:EnableKeyRotation',
        'kms:DisableKeyRotation',
        'kms:TagResource',
        'kms:UntagResource'
    ]
    
    # Administrative actions that should be restricted
    admin_kms_actions = [
        'kms:CreateGrant',
        'kms:RetireGrant',
        'kms:RevokeGrant'
    ]
    
    if not isinstance(policy_document, dict) or 'Statement' not in policy_document:
        return {'status': 'COMPLIANT', 'issues': [], 'details': {}}
    
    statements = policy_document.get('Statement', [])
    if not isinstance(statements, list):
        statements = [statements]
    
    policy_issues = []
    dangerous_permissions = []
    admin_permissions = []
    wildcard_resources = []
    
    for i, statement in enumerate(statements):
        if not isinstance(statement, dict):
            continue
            
        effect = statement.get('Effect', '').upper()
        if effect != 'ALLOW':
            continue
            
        actions = statement.get('Action', [])
        if isinstance(actions, str):
            actions = [actions]
        elif not isinstance(actions, list):
            continue
            
        resources = statement.get('Resource', [])
        if isinstance(resources, str):
            resources = [resources]
        elif not isinstance(resources, list):
            resources = []
            
        # Check for dangerous KMS actions
        for action in actions:
            action_lower = action.lower()
            
            # Check for wildcard KMS access
            if action_lower == 'kms:*':
                dangerous_permissions.append({
                    'statement_index': i,
                    'action': action,
                    'severity': 'CRITICAL',
                    'description': 'Grants full access to all KMS operations'
                })
                
            # Check for specific dangerous actions
            for dangerous_action in dangerous_kms_actions:
                if action_lower == dangerous_action.lower():
                    dangerous_permissions.append({
                        'statement_index': i,
                        'action': action,
                        'severity': 'HIGH',
                        'description': f'Grants dangerous KMS permission: {action}'
                    })
                    
            # Check for administrative actions
            for admin_action in admin_kms_actions:
                if action_lower == admin_action.lower():
                    admin_permissions.append({
                        'statement_index': i,
                        'action': action,
                        'severity': 'MEDIUM',
                        'description': f'Grants administrative KMS permission: {action}'
                    })
                    
        # Check for wildcard resources with KMS actions
        kms_actions_in_statement = [a for a in actions if a.lower().startswith('kms:')]
        if kms_actions_in_statement and resources:
            for resource in resources:
                if resource == '*':
                    wildcard_resources.append({
                        'statement_index': i,
                        'actions': kms_actions_in_statement,
                        'resource': resource,
                        'severity': 'HIGH',
                        'description': 'KMS actions granted on all resources using wildcard'
                    })
    
    # Compile all issues
    all_issues = dangerous_permissions + admin_permissions + wildcard_resources
    
    if all_issues:
        status = 'NON_COMPLIANT'
        
        # Determine overall severity
        if any(issue.get('severity') == 'CRITICAL' for issue in all_issues):
            severity = 'CRITICAL'
        elif any(issue.get('severity') == 'HIGH' for issue in all_issues):
            severity = 'HIGH'
        else:
            severity = 'MEDIUM'
    else:
        status = 'COMPLIANT'
        severity = 'LOW'
    
    return {
        'status': status,
        'severity': severity,
        'issues': all_issues,
        'details': {
            'policy_name': policy_name,
            'entity_type': entity_type,
            'entity_name': entity_name,
            'dangerous_permissions_count': len(dangerous_permissions),
            'admin_permissions_count': len(admin_permissions),
            'wildcard_resources_count': len(wildcard_resources),
            'total_issues': len(all_issues)
        }
    }

def iam_policy_no_full_access_to_kms_check(iam_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for iam_policy_no_full_access_to_kms.
    
    Args:
        iam_client: Boto3 IAM client (auto-created by framework)
        region (str): AWS region (auto-managed by framework)
        profile (str): AWS profile name (auto-managed by framework)
        logger: Logger instance (auto-configured by framework)
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    try:
        logger.info(f"Checking IAM policies for KMS full access in region {region}")
        
        # Check User Policies
        try:
            users_response = iam_client.list_users()
            users = users_response.get('Users', [])
            
            for user in users:
                user_name = user.get('UserName', 'unknown')
                
                try:
                    # Check inline user policies
                    user_policies_response = iam_client.list_user_policies(UserName=user_name)
                    policy_names = user_policies_response.get('PolicyNames', [])
                    
                    for policy_name in policy_names:
                        try:
                            policy_response = iam_client.get_user_policy(
                                UserName=user_name,
                                PolicyName=policy_name
                            )
                            
                            policy_document = policy_response.get('PolicyDocument', {})
                            
                            # Analyze policy for KMS permissions
                            analysis = check_policy_for_kms_full_access(
                                policy_document, policy_name, 'User', user_name
                            )
                            
                            if analysis['status'] == 'NON_COMPLIANT':
                                finding = {
                                    'region': region,
                                    'profile': profile,
                                    'resource_type': 'IAM User Policy',
                                    'resource_id': f"{user_name}:{policy_name}",
                                    'status': 'NON_COMPLIANT',
                                    'compliance_status': 'FAIL',
                                    'risk_level': analysis.get('severity', 'HIGH'),
                                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Remove excessive KMS permissions'),
                                    'details': {
                                        'user_name': user_name,
                                        'policy_name': policy_name,
                                        'policy_type': 'inline',
                                        'entity_type': 'User',
                                        'issues': analysis['issues'],
                                        'issue_summary': analysis['details'],
                                        'security_risk': 'Excessive KMS permissions could allow unauthorized access to encryption keys',
                                        'remediation_steps': [
                                            'Review the policy and identify specific KMS operations needed',
                                            'Replace wildcard permissions with specific actions',
                                            'Limit resource access using specific key ARNs',
                                            'Remove administrative permissions if not required',
                                            'Consider using managed policies with appropriate permissions',
                                            'Implement condition statements for additional restrictions'
                                        ]
                                    }
                                }
                                findings.append(finding)
                                
                        except Exception as e:
                            logger.warning(f"Error checking user policy {policy_name} for user {user_name}: {e}")
                            
                except Exception as e:
                    logger.warning(f"Error checking policies for user {user_name}: {e}")
                    
        except Exception as e:
            logger.warning(f"Error listing users: {e}")
        
        # Check Role Policies
        try:
            roles_response = iam_client.list_roles()
            roles = roles_response.get('Roles', [])
            
            for role in roles:
                role_name = role.get('RoleName', 'unknown')
                
                try:
                    # Check inline role policies
                    role_policies_response = iam_client.list_role_policies(RoleName=role_name)
                    policy_names = role_policies_response.get('PolicyNames', [])
                    
                    for policy_name in policy_names:
                        try:
                            policy_response = iam_client.get_role_policy(
                                RoleName=role_name,
                                PolicyName=policy_name
                            )
                            
                            policy_document = policy_response.get('PolicyDocument', {})
                            
                            # Analyze policy for KMS permissions
                            analysis = check_policy_for_kms_full_access(
                                policy_document, policy_name, 'Role', role_name
                            )
                            
                            if analysis['status'] == 'NON_COMPLIANT':
                                finding = {
                                    'region': region,
                                    'profile': profile,
                                    'resource_type': 'IAM Role Policy',
                                    'resource_id': f"{role_name}:{policy_name}",
                                    'status': 'NON_COMPLIANT',
                                    'compliance_status': 'FAIL',
                                    'risk_level': analysis.get('severity', 'HIGH'),
                                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Remove excessive KMS permissions'),
                                    'details': {
                                        'role_name': role_name,
                                        'policy_name': policy_name,
                                        'policy_type': 'inline',
                                        'entity_type': 'Role',
                                        'issues': analysis['issues'],
                                        'issue_summary': analysis['details'],
                                        'security_risk': 'Excessive KMS permissions in role could allow unauthorized key access when role is assumed',
                                        'remediation_steps': [
                                            'Review the role policy and identify specific KMS operations needed',
                                            'Replace wildcard permissions with specific actions',
                                            'Limit resource access using specific key ARNs',
                                            'Remove administrative permissions if not required',
                                            'Add condition statements to restrict key usage',
                                            'Consider using separate roles for different KMS operations'
                                        ]
                                    }
                                }
                                findings.append(finding)
                                
                        except Exception as e:
                            logger.warning(f"Error checking role policy {policy_name} for role {role_name}: {e}")
                            
                except Exception as e:
                    logger.warning(f"Error checking policies for role {role_name}: {e}")
                    
        except Exception as e:
            logger.warning(f"Error listing roles: {e}")
        
        # Check Group Policies
        try:
            groups_response = iam_client.list_groups()
            groups = groups_response.get('Groups', [])
            
            for group in groups:
                group_name = group.get('GroupName', 'unknown')
                
                try:
                    # Check inline group policies
                    group_policies_response = iam_client.list_group_policies(GroupName=group_name)
                    policy_names = group_policies_response.get('PolicyNames', [])
                    
                    for policy_name in policy_names:
                        try:
                            policy_response = iam_client.get_group_policy(
                                GroupName=group_name,
                                PolicyName=policy_name
                            )
                            
                            policy_document = policy_response.get('PolicyDocument', {})
                            
                            # Analyze policy for KMS permissions
                            analysis = check_policy_for_kms_full_access(
                                policy_document, policy_name, 'Group', group_name
                            )
                            
                            if analysis['status'] == 'NON_COMPLIANT':
                                finding = {
                                    'region': region,
                                    'profile': profile,
                                    'resource_type': 'IAM Group Policy',
                                    'resource_id': f"{group_name}:{policy_name}",
                                    'status': 'NON_COMPLIANT',
                                    'compliance_status': 'FAIL',
                                    'risk_level': analysis.get('severity', 'HIGH'),
                                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Remove excessive KMS permissions'),
                                    'details': {
                                        'group_name': group_name,
                                        'policy_name': policy_name,
                                        'policy_type': 'inline',
                                        'entity_type': 'Group',
                                        'issues': analysis['issues'],
                                        'issue_summary': analysis['details'],
                                        'security_risk': 'Excessive KMS permissions in group policy affect all group members',
                                        'remediation_steps': [
                                            'Review the group policy and identify specific KMS operations needed',
                                            'Replace wildcard permissions with specific actions',
                                            'Limit resource access using specific key ARNs',
                                            'Remove administrative permissions if not required',
                                            'Consider creating separate groups for different access levels',
                                            'Implement condition statements for additional security'
                                        ]
                                    }
                                }
                                findings.append(finding)
                                
                        except Exception as e:
                            logger.warning(f"Error checking group policy {policy_name} for group {group_name}: {e}")
                            
                except Exception as e:
                    logger.warning(f"Error checking policies for group {group_name}: {e}")
                    
        except Exception as e:
            logger.warning(f"Error listing groups: {e}")
        
        if not findings:
            logger.info(f"No IAM policies with excessive KMS permissions found in region {region}")
        
    except Exception as e:
        logger.error(f"Error in iam_policy_no_full_access_to_kms check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'IAM Policy',
            'status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Review and remediate as needed'),
            'error': str(e)
        })
        
    return findings

def iam_policy_no_full_access_to_kms(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=iam_policy_no_full_access_to_kms_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = iam_policy_no_full_access_to_kms(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

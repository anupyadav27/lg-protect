#!/usr/bin/env python3
"""
data_security_aws - awslambda_function_resource_policy_restricted

Ensure Lambda function resource policies follow least privilege principles and do not grant excessive permissions.
"""

# Rule Metadata from YAML:
# Function Name: awslambda_function_resource_policy_restricted
# Capability: ACCESS_GOVERNANCE
# Service: LAMBDA
# Subservice: POLICY
# Description: Ensure Lambda function resource policies follow least privilege principles and do not grant excessive permissions.
# Risk Level: MEDIUM
# Recommendation: Restrict Lambda function resource policies
# API Function: client = boto3.client('lambda')
# User Function: awslambda_function_resource_policy_restricted()

# Import required modules
import boto3
import json
import sys
from typing import Dict, List, Any
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def load_rule_metadata(function_name: str) -> Dict[str, Any]:
    """Load rule metadata from YAML configuration."""
    return {
        "function_name": "awslambda_function_resource_policy_restricted",
        "title": "Restrict Lambda function resource policies",
        "description": "Ensure Lambda function resource policies follow least privilege principles and do not grant excessive permissions.",
        "capability": "access_governance",
        "service": "lambda",
        "subservice": "policy",
        "risk": "MEDIUM",
        "existing": False
    }

def awslambda_function_resource_policy_restricted_check(region_name: str, profile_name: str = None) -> List[Dict[str, Any]]:
    """
    Check lambda resources for access_governance compliance.
    
    Args:
        region_name (str): AWS region name
        profile_name (str): AWS profile name (optional)
        
    Returns:
        List[Dict]: List of compliance findings
    """
    findings = []
    
    try:
        # Initialize boto3 client
        session = boto3.Session(profile_name=profile_name)
        lambda_client = session.client('lambda', region_name=region_name)
        
        logger.info(f"Checking lambda resources for access_governance compliance in region {region_name}")
        
        # Get all Lambda functions in the region
        paginator = lambda_client.get_paginator('list_functions')
        
        for page in paginator.paginate():
            for function in page['Functions']:
                function_name = function.get('FunctionName')
                function_arn = function.get('FunctionArn')
                
                try:
                    # Check if function has a resource-based policy
                    try:
                        policy_response = lambda_client.get_policy(FunctionName=function_name)
                        policy_document = json.loads(policy_response.get('Policy', '{}'))
                    except lambda_client.exceptions.ResourceNotFoundException:
                        # No resource policy exists - this is actually good for security
                        findings.append({
                            "region": region_name,
                            "profile": profile_name or "default",
                            "resource_type": "lambda_function",
                            "resource_id": function_arn,
                            "status": "COMPLIANT",
                            "risk_level": "MEDIUM",
                            "recommendation": "Lambda function has no resource policy (good for security)",
                            "details": {
                                "function_name": function_name,
                                "function_arn": function_arn,
                                "has_resource_policy": False,
                                "runtime": function.get('Runtime'),
                                "last_modified": function.get('LastModified')
                            }
                        })
                        continue
                    
                    # Analyze the resource policy for security violations
                    policy_violations = []
                    policy_analysis = {
                        'function_name': function_name,
                        'function_arn': function_arn,
                        'has_resource_policy': True,
                        'statements_count': 0,
                        'principals_analysis': [],
                        'actions_analysis': [],
                        'conditions_analysis': [],
                        'security_issues': []
                    }
                    
                    statements = policy_document.get('Statement', [])
                    if isinstance(statements, dict):
                        statements = [statements]
                    
                    policy_analysis['statements_count'] = len(statements)
                    
                    for stmt_index, statement in enumerate(statements):
                        statement_id = statement.get('Sid', f'Statement-{stmt_index}')
                        effect = statement.get('Effect', 'Deny')
                        
                        # Check principals
                        principals = statement.get('Principal', {})
                        if isinstance(principals, str):
                            principals = {'AWS': principals}
                        
                        principal_issues = []
                        
                        # Check for wildcard principals
                        if principals == '*' or (isinstance(principals, dict) and principals.get('AWS') == '*'):
                            policy_violations.append({
                                'statement_id': statement_id,
                                'violation_type': 'wildcard_principal',
                                'message': 'Statement allows access from any principal (*)',
                                'severity': 'HIGH'
                            })
                            principal_issues.append('wildcard_principal')
                        
                        # Check for overly broad AWS principals
                        if isinstance(principals, dict):
                            aws_principals = principals.get('AWS', [])
                            if isinstance(aws_principals, str):
                                aws_principals = [aws_principals]
                            
                            for principal in aws_principals:
                                if ':root' in principal and not principal.endswith(':root'):
                                    # Account root but not specific user/role
                                    policy_violations.append({
                                        'statement_id': statement_id,
                                        'violation_type': 'account_root_principal',
                                        'message': f'Statement allows access from account root: {principal}',
                                        'severity': 'MEDIUM'
                                    })
                                    principal_issues.append('account_root_access')
                                
                                if '*' in principal and principal != '*':
                                    policy_violations.append({
                                        'statement_id': statement_id,
                                        'violation_type': 'wildcard_in_principal',
                                        'message': f'Statement contains wildcard in principal: {principal}',
                                        'severity': 'MEDIUM'
                                    })
                                    principal_issues.append('wildcard_in_principal')
                        
                        policy_analysis['principals_analysis'].append({
                            'statement_id': statement_id,
                            'principals': principals,
                            'issues': principal_issues
                        })
                        
                        # Check actions
                        actions = statement.get('Action', [])
                        if isinstance(actions, str):
                            actions = [actions]
                        
                        action_issues = []
                        sensitive_actions = [
                            'lambda:*',
                            'lambda:InvokeFunction',
                            'lambda:UpdateFunctionCode',
                            'lambda:UpdateFunctionConfiguration',
                            'lambda:CreateFunction',
                            'lambda:DeleteFunction'
                        ]
                        
                        for action in actions:
                            if action == '*':
                                policy_violations.append({
                                    'statement_id': statement_id,
                                    'violation_type': 'wildcard_action',
                                    'message': 'Statement allows all actions (*)',
                                    'severity': 'HIGH'
                                })
                                action_issues.append('wildcard_action')
                            elif action in sensitive_actions:
                                policy_violations.append({
                                    'statement_id': statement_id,
                                    'violation_type': 'sensitive_action',
                                    'message': f'Statement allows sensitive action: {action}',
                                    'severity': 'MEDIUM'
                                })
                                action_issues.append('sensitive_action')
                        
                        policy_analysis['actions_analysis'].append({
                            'statement_id': statement_id,
                            'actions': actions,
                            'issues': action_issues
                        })
                        
                        # Check conditions
                        conditions = statement.get('Condition', {})
                        condition_issues = []
                        
                        if not conditions and effect == 'Allow':
                            policy_violations.append({
                                'statement_id': statement_id,
                                'violation_type': 'no_conditions',
                                'message': 'Allow statement has no conditions to restrict access',
                                'severity': 'MEDIUM'
                            })
                            condition_issues.append('no_conditions')
                        
                        # Check for IP address restrictions
                        has_ip_restriction = False
                        has_vpc_restriction = False
                        has_time_restriction = False
                        
                        for condition_type, condition_values in conditions.items():
                            if 'IpAddress' in condition_type or 'IpAddressIfExists' in condition_type:
                                has_ip_restriction = True
                            elif 'vpc' in condition_type.lower() or 'Vpc' in condition_type:
                                has_vpc_restriction = True
                            elif 'Date' in condition_type or 'Time' in condition_type:
                                has_time_restriction = True
                        
                        policy_analysis['conditions_analysis'].append({
                            'statement_id': statement_id,
                            'conditions': conditions,
                            'has_ip_restriction': has_ip_restriction,
                            'has_vpc_restriction': has_vpc_restriction,
                            'has_time_restriction': has_time_restriction,
                            'issues': condition_issues
                        })
                    
                    # Check for cross-account access
                    cross_account_access = False
                    function_account = function_arn.split(':')[4]
                    
                    for principal_analysis in policy_analysis['principals_analysis']:
                        principals = principal_analysis['principals']
                        if isinstance(principals, dict):
                            aws_principals = principals.get('AWS', [])
                            if isinstance(aws_principals, str):
                                aws_principals = [aws_principals]
                            
                            for principal in aws_principals:
                                if ':' in principal and principal.split(':')[4] != function_account:
                                    cross_account_access = True
                                    policy_violations.append({
                                        'statement_id': principal_analysis['statement_id'],
                                        'violation_type': 'cross_account_access',
                                        'message': f'Statement allows cross-account access from: {principal}',
                                        'severity': 'HIGH'
                                    })
                                    break
                    
                    policy_analysis['cross_account_access'] = cross_account_access
                    policy_analysis['security_issues'] = policy_violations
                    
                    # Determine compliance status
                    high_severity_violations = [v for v in policy_violations if v.get('severity') == 'HIGH']
                    medium_severity_violations = [v for v in policy_violations if v.get('severity') == 'MEDIUM']
                    
                    if high_severity_violations or len(medium_severity_violations) > 2:
                        findings.append({
                            "region": region_name,
                            "profile": profile_name or "default",
                            "resource_type": "lambda_function",
                            "resource_id": function_arn,
                            "status": "NON_COMPLIANT",
                            "risk_level": "MEDIUM",
                            "recommendation": "Restrict Lambda function resource policy to follow least privilege principles",
                            "details": {
                                **policy_analysis,
                                "violation": f"Resource policy has {len(high_severity_violations)} high and {len(medium_severity_violations)} medium severity violations",
                                "policy_violations": policy_violations,
                                "violation_summary": {
                                    'high_severity': len(high_severity_violations),
                                    'medium_severity': len(medium_severity_violations),
                                    'total': len(policy_violations)
                                },
                                "runtime": function.get('Runtime'),
                                "last_modified": function.get('LastModified')
                            }
                        })
                    else:
                        findings.append({
                            "region": region_name,
                            "profile": profile_name or "default",
                            "resource_type": "lambda_function",
                            "resource_id": function_arn,
                            "status": "COMPLIANT",
                            "risk_level": "MEDIUM",
                            "recommendation": "Lambda function resource policy follows acceptable security practices",
                            "details": {
                                **policy_analysis,
                                "minor_issues": medium_severity_violations if medium_severity_violations else None,
                                "violation_summary": {
                                    'high_severity': len(high_severity_violations),
                                    'medium_severity': len(medium_severity_violations),
                                    'total': len(policy_violations)
                                },
                                "runtime": function.get('Runtime'),
                                "last_modified": function.get('LastModified')
                            }
                        })
                        
                except Exception as func_error:
                    logger.warning(f"Failed to check function {function_name}: {func_error}")
                    findings.append({
                        "region": region_name,
                        "profile": profile_name or "default",
                        "resource_type": "lambda_function",
                        "resource_id": function_arn,
                        "status": "ERROR",
                        "risk_level": "MEDIUM",
                        "recommendation": "Unable to check resource policy restrictions",
                        "details": {
                            "function_name": function_name,
                            "function_arn": function_arn,
                            "error": str(func_error)
                        }
                    })
        
        logger.info(f"Completed checking awslambda_function_resource_policy_restricted. Found {len(findings)} findings.")
        
    except Exception as e:
        logger.error(f"Failed to check awslambda_function_resource_policy_restricted: {e}")
        findings.append({
            "region": region_name,
            "profile": profile_name or "default",
            "resource_type": "lambda_function",
            "resource_id": "unknown",
            "status": "ERROR",
            "risk_level": "MEDIUM",
            "recommendation": "Fix API access issues",
            "details": {
                "error": str(e)
            }
        })
    
    return findings

def awslambda_function_resource_policy_restricted(region_name: str, profile_name: str = None) -> Dict[str, Any]:
    """
    Main function wrapper for awslambda_function_resource_policy_restricted.
    
    Args:
        region_name (str): AWS region name
        profile_name (str): AWS profile name (optional)
        
    Returns:
        Dict: Results summary
    """
    COMPLIANCE_DATA = load_rule_metadata("awslambda_function_resource_policy_restricted")
    
    # TODO: Implement SecurityEngine integration when available
    # from data_security_engine import SecurityEngine
    # engine = SecurityEngine(COMPLIANCE_DATA)
    # return engine.run_check(region_name, profile_name, awslambda_function_resource_policy_restricted_check)
    
    # Current implementation
    findings = awslambda_function_resource_policy_restricted_check(region_name, profile_name)
    
    # Calculate compliance statistics
    total_findings = len(findings)
    compliant_findings = len([f for f in findings if f['status'] == 'COMPLIANT'])
    non_compliant_findings = len([f for f in findings if f['status'] == 'NON_COMPLIANT'])
    error_findings = len([f for f in findings if f['status'] == 'ERROR'])
    
    return {
        "function_name": "awslambda_function_resource_policy_restricted",
        "region": region_name,
        "profile": profile_name or "default",
        "total_findings": total_findings,
        "compliant_count": compliant_findings,
        "non_compliant_count": non_compliant_findings,
        "error_count": error_findings,
        "compliance_rate": (compliant_findings / total_findings * 100) if total_findings > 0 else 0,
        "findings": findings
    }

def main():
    """CLI entry point for awslambda_function_resource_policy_restricted."""
    # TODO: Implement setup_command_line_interface() when data_security_engine is available
    # from data_security_engine import setup_command_line_interface, save_results, exit_with_status
    # args = setup_command_line_interface()
    # results = awslambda_function_resource_policy_restricted(args.region, args.profile)
    # save_results(results, args.output_file)
    # exit_with_status(results)
    
    # Current CLI implementation
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Ensure Lambda function resource policies follow least privilege principles and do not grant excessive permissions."
    )
    parser.add_argument("--region", default="us-east-1", help="AWS region")
    parser.add_argument("--profile", help="AWS profile name")
    parser.add_argument("--output", help="Output file for results (JSON format)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        results = awslambda_function_resource_policy_restricted(args.region, args.profile)
        
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"Results saved to {args.output}")
        else:
            print(json.dumps(results, indent=2))
            
        # Exit with appropriate code
        if results['error_count'] > 0:
            sys.exit(2)  # Errors encountered
        elif results['non_compliant_count'] > 0:
            sys.exit(1)  # Non-compliant resources found
        else:
            sys.exit(0)  # All compliant
            
    except Exception as e:
        logger.error(f"Execution failed: {e}")
        sys.exit(3)

if __name__ == "__main__":
    main()

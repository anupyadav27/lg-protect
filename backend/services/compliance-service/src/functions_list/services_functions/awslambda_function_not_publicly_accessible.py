#!/usr/bin/env python3
"""
aws_foundational_security_best_practices_aws - lambda_function_public_access_prohibited

Lambda function policies should prohibit public access
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
    """Load compliance metadata from compliance_checks.json."""
    try:
        compliance_json_path = os.path.join(
            os.path.dirname(__file__), '..', '..', 'compliance_checks.json'
        )
        
        with open(compliance_json_path, 'r') as f:
            compliance_data = json.load(f)
        
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
        
    return {
        'compliance_name': 'aws_foundational_security_best_practices_aws',
        'function_name': 'lambda_function_public_access_prohibited',
        'id': 'Lambda.1',
        'name': 'Lambda function policies should prohibit public access',
        'description': 'Lambda function policies should prohibit public access',
        'api_function': 'client = boto3.client(\'lambda\')',
        'user_function': 'list_functions(), get_policy()',
        'risk_level': 'CRITICAL',
        'recommendation': 'Remove public access from Lambda function policies'
    }

COMPLIANCE_DATA = load_compliance_metadata('lambda_function_public_access_prohibited')

def lambda_function_public_access_prohibited_check(lambda_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for lambda_function_public_access_prohibited.
    """
    findings = []
    
    try:
        # Get all Lambda functions
        paginator = lambda_client.get_paginator('list_functions')
        functions = []
        
        for page in paginator.paginate():
            functions.extend(page.get('Functions', []))
        
        if not functions:
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'Lambda Function',
                'resource_id': f'no-functions-{region}',
                'status': 'COMPLIANT',
                'compliance_status': 'PASS',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'CRITICAL'),
                'recommendation': COMPLIANCE_DATA.get('recommendation', 'Remove public access from Lambda function policies'),
                'details': {
                    'message': 'No Lambda functions found in this region',
                    'function_count': 0
                }
            }
            findings.append(finding)
            return findings
        
        # Check each function for public access
        for function in functions:
            function_name = function.get('FunctionName')
            function_arn = function.get('FunctionArn')
            
            try:
                # Get function policy
                policy_response = lambda_client.get_policy(FunctionName=function_name)
                policy_document = json.loads(policy_response.get('Policy', '{}'))
                
                # Check for public access in policy
                has_public_access = False
                public_principals = []
                
                statements = policy_document.get('Statement', [])
                if not isinstance(statements, list):
                    statements = [statements]
                
                for statement in statements:
                    principal = statement.get('Principal', {})
                    
                    # Check for wildcard principals
                    if principal == '*' or principal == ['*']:
                        has_public_access = True
                        public_principals.append('*')
                    elif isinstance(principal, dict):
                        # Check AWS principals
                        aws_principals = principal.get('AWS', [])
                        if not isinstance(aws_principals, list):
                            aws_principals = [aws_principals]
                        
                        for aws_principal in aws_principals:
                            if aws_principal == '*' or aws_principal == 'arn:aws:iam::*:root':
                                has_public_access = True
                                public_principals.append(aws_principal)
                    elif isinstance(principal, str) and principal == '*':
                        has_public_access = True
                        public_principals.append(principal)
                
                # Determine compliance status
                if has_public_access:
                    status = 'NON_COMPLIANT'
                    compliance_status = 'FAIL'
                    message = f'Lambda function {function_name} has public access'
                else:
                    status = 'COMPLIANT'
                    compliance_status = 'PASS'
                    message = f'Lambda function {function_name} does not have public access'
                
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'Lambda Function',
                    'resource_id': function_arn,
                    'status': status,
                    'compliance_status': compliance_status,
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'CRITICAL'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Remove public access from Lambda function policies'),
                    'details': {
                        'function_name': function_name,
                        'function_arn': function_arn,
                        'has_public_access': has_public_access,
                        'public_principals': public_principals,
                        'runtime': function.get('Runtime'),
                        'message': message
                    }
                }
                findings.append(finding)
                
            except lambda_client.exceptions.ResourceNotFoundException:
                # Function has no policy - this is compliant
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'Lambda Function',
                    'resource_id': function_arn,
                    'status': 'COMPLIANT',
                    'compliance_status': 'PASS',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'CRITICAL'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Remove public access from Lambda function policies'),
                    'details': {
                        'function_name': function_name,
                        'function_arn': function_arn,
                        'has_public_access': False,
                        'has_policy': False,
                        'runtime': function.get('Runtime'),
                        'message': f'Lambda function {function_name} has no resource policy'
                    }
                }
                findings.append(finding)
                
            except Exception as e:
                logger.error(f"Error checking policy for function {function_name}: {e}")
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'Lambda Function',
                    'resource_id': function_arn,
                    'status': 'ERROR',
                    'compliance_status': 'ERROR',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'CRITICAL'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Remove public access from Lambda function policies'),
                    'error': str(e),
                    'details': {
                        'function_name': function_name,
                        'function_arn': function_arn,
                        'message': f'Error checking policy for function {function_name}'
                    }
                }
                findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in lambda_function_public_access_prohibited check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'Lambda Function',
            'resource_id': f'error-{region}',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'CRITICAL'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Remove public access from Lambda function policies'),
            'error': str(e)
        })
        
    return findings

def lambda_function_public_access_prohibited(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=lambda_function_public_access_prohibited_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    args = setup_command_line_interface(COMPLIANCE_DATA)
    results = lambda_function_public_access_prohibited(
        profile_name=args.profile,
        region_name=args.region
    )
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

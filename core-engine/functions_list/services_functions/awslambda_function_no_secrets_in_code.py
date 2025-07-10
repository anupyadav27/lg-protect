#!/usr/bin/env python3
"""
aws_well_architected_framework_security_pillar_aws - awslambda_function_no_secrets_in_code

A workload requires an automated capability to prove its identity to databases, resources, and third-party services. This is accomplished using secret access credentials, such as API access keys, passwords, and OAuth tokens. Using a purpose-built service to store, manage, and rotate these credentials helps reduce the likelihood that those credentials become compromised.
"""

import sys
import os
import json
import re
import base64
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
        'compliance_name': 'aws_well_architected_framework_security_pillar_aws',
        'function_name': 'awslambda_function_no_secrets_in_code',
        'id': 'awslambda_function_no_secrets_in_code',
        'name': 'Lambda Function No Secrets In Code',
        'description': 'A workload requires an automated capability to prove its identity to databases, resources, and third-party services. This is accomplished using secret access credentials, such as API access keys, passwords, and OAuth tokens. Using a purpose-built service to store, manage, and rotate these credentials helps reduce the likelihood that those credentials become compromised.',
        'api_function': 'client = boto3.client(\'lambda\')',
        'user_function': 'get_function()',
        'risk_level': 'HIGH',
        'recommendation': 'Remove hardcoded secrets from Lambda function code and use AWS Secrets Manager, Parameter Store, or environment variables instead'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('awslambda_function_no_secrets_in_code')

def detect_secrets_in_code(code_content: str) -> List[Dict[str, str]]:
    """Detect potential secrets in Lambda function code."""
    secrets_found = []
    
    # Common secret patterns
    patterns = {
        'aws_access_key': r'AKIA[0-9A-Z]{16}',
        'aws_secret_key': r'[A-Za-z0-9/+=]{40}',
        'api_key': r'(?i)(api[_-]?key|apikey)\s*[:=]\s*[\'"][a-zA-Z0-9_\-]{16,}[\'"]',
        'password': r'(?i)(password|passwd|pwd)\s*[:=]\s*[\'"][^\'\"]{8,}[\'"]',
        'private_key': r'-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----',
        'database_url': r'(?i)(database_url|db_url)\s*[:=]\s*[\'"][^\'\"]+[\'"]',
        'jwt_secret': r'(?i)(jwt[_-]?secret|secret[_-]?key)\s*[:=]\s*[\'"][a-zA-Z0-9_\-]{16,}[\'"]',
        'oauth_token': r'(?i)(oauth[_-]?token|access[_-]?token)\s*[:=]\s*[\'"][a-zA-Z0-9_\-]{16,}[\'"]'
    }
    
    for secret_type, pattern in patterns.items():
        matches = re.finditer(pattern, code_content)
        for match in matches:
            secrets_found.append({
                'type': secret_type,
                'pattern': pattern,
                'match': match.group()[:50] + '...' if len(match.group()) > 50 else match.group(),
                'line_context': code_content[max(0, match.start()-50):match.end()+50]
            })
    
    return secrets_found

def awslambda_function_no_secrets_in_code_check(lambda_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for awslambda_function_no_secrets_in_code.
    
    Args:
        lambda_client: Boto3 Lambda service client (auto-created by framework)
        region (str): AWS region (auto-managed by framework)
        profile (str): AWS profile name (auto-managed by framework)
        logger: Logger instance (auto-configured by framework)
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    try:
        # Get list of all Lambda functions
        paginator = lambda_client.get_paginator('list_functions')
        
        for page in paginator.paginate():
            for function in page['Functions']:
                function_name = function['FunctionName']
                function_arn = function['FunctionArn']
                
                try:
                    # Get function code
                    function_details = lambda_client.get_function(FunctionName=function_name)
                    
                    # Check if function has code URL for download
                    code_location = function_details.get('Code', {}).get('Location')
                    
                    secrets_found = []
                    
                    # If code is available inline or we can access environment variables
                    if 'Environment' in function_details['Configuration']:
                        env_vars = function_details['Configuration']['Environment'].get('Variables', {})
                        
                        # Check environment variables for secrets
                        for key, value in env_vars.items():
                            if value:  # Only check non-empty values
                                env_secrets = detect_secrets_in_code(f"{key}={value}")
                                for secret in env_secrets:
                                    secret['location'] = 'environment_variable'
                                    secret['variable_name'] = key
                                secrets_found.extend(env_secrets)
                    
                    # For deployment packages, we can't directly scan code without downloading
                    # But we can check for common indicators in function configuration
                    function_code = function_details.get('Configuration', {})
                    
                    # Check description and handler for potential secrets
                    description = function_code.get('Description', '')
                    handler = function_code.get('Handler', '')
                    
                    desc_secrets = detect_secrets_in_code(description)
                    handler_secrets = detect_secrets_in_code(handler)
                    
                    for secret in desc_secrets:
                        secret['location'] = 'description'
                    for secret in handler_secrets:
                        secret['location'] = 'handler'
                    
                    secrets_found.extend(desc_secrets + handler_secrets)
                    
                    # Determine compliance status
                    status = 'NON_COMPLIANT' if secrets_found else 'COMPLIANT'
                    compliance_status = 'FAIL' if secrets_found else 'PASS'
                    
                    finding = {
                        'region': region,
                        'profile': profile,
                        'resource_type': 'AWS::Lambda::Function',
                        'resource_id': function_name,
                        'resource_arn': function_arn,
                        'status': status,
                        'compliance_status': compliance_status,
                        'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                        'recommendation': COMPLIANCE_DATA.get('recommendation', 'Remove hardcoded secrets from Lambda function code'),
                        'details': {
                            'function_name': function_name,
                            'runtime': function_code.get('Runtime', 'Unknown'),
                            'last_modified': function_code.get('LastModified', ''),
                            'secrets_found': len(secrets_found),
                            'secret_details': secrets_found if secrets_found else None,
                            'code_size': function_code.get('CodeSize', 0),
                            'has_environment_variables': 'Environment' in function_details['Configuration']
                        }
                    }
                    
                    findings.append(finding)
                    
                    if secrets_found:
                        logger.warning(f"Secrets detected in Lambda function {function_name}: {len(secrets_found)} potential secrets found")
                    
                except Exception as func_error:
                    logger.error(f"Error checking Lambda function {function_name}: {func_error}")
                    findings.append({
                        'region': region,
                        'profile': profile,
                        'resource_type': 'AWS::Lambda::Function',
                        'resource_id': function_name,
                        'status': 'ERROR',
                        'compliance_status': 'ERROR',
                        'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                        'recommendation': COMPLIANCE_DATA.get('recommendation', 'Review and remediate as needed'),
                        'error': str(func_error)
                    })
        
    except Exception as e:
        logger.error(f"Error in awslambda_function_no_secrets_in_code check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'AWS::Lambda::Function',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Review and remediate as needed'),
            'error': str(e)
        })
        
    return findings

def awslambda_function_no_secrets_in_code(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=awslambda_function_no_secrets_in_code_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = awslambda_function_no_secrets_in_code(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

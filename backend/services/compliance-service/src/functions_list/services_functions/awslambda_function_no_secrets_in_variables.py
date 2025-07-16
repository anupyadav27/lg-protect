#!/usr/bin/env python3
"""
aws_well_architected_framework_security_pillar_aws - awslambda_function_no_secrets_in_variables

A workload requires an automated capability to prove its identity to databases, resources, and third-party services. This is accomplished using secret access credentials, such as API access keys, passwords, and OAuth tokens. Using a purpose-built service to store, manage, and rotate these credentials helps reduce the likelihood that those credentials become compromised.
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
        'compliance_name': 'aws_well_architected_framework_security_pillar_aws',
        'function_name': 'awslambda_function_no_secrets_in_variables',
        'id': 'SEC.5',
        'name': 'Lambda functions should not store secrets in environment variables',
        'description': 'Using a purpose-built service to store, manage, and rotate credentials helps reduce the likelihood that those credentials become compromised',
        'api_function': 'client = boto3.client("lambda")',
        'user_function': 'list_functions(), get_function_configuration()',
        'risk_level': 'HIGH',
        'recommendation': 'Use AWS Secrets Manager or Systems Manager Parameter Store instead of environment variables for secrets'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('awslambda_function_no_secrets_in_variables')

def detect_secrets_in_environment_variables(env_vars: Dict[str, str]) -> List[Dict[str, Any]]:
    """
    Detect potential secrets in Lambda environment variables.
    
    Args:
        env_vars: Dictionary of environment variable names and values
        
    Returns:
        List of detected secrets with details
    """
    potential_secrets = []
    
    # Common secret patterns
    secret_patterns = {
        'api_key': re.compile(r'(api[_-]?key|apikey)', re.IGNORECASE),
        'password': re.compile(r'(password|passwd|pwd)', re.IGNORECASE),
        'secret': re.compile(r'(secret|token)', re.IGNORECASE),
        'private_key': re.compile(r'(private[_-]?key|privatekey)', re.IGNORECASE),
        'access_key': re.compile(r'(access[_-]?key|accesskey)', re.IGNORECASE),
        'auth': re.compile(r'(auth|authorization)', re.IGNORECASE),
        'credential': re.compile(r'(credential|cred)', re.IGNORECASE),
        'oauth': re.compile(r'(oauth)', re.IGNORECASE),
        'jwt': re.compile(r'(jwt|token)', re.IGNORECASE),
        'database_url': re.compile(r'(database[_-]?url|db[_-]?url)', re.IGNORECASE),
        'connection_string': re.compile(r'(connection[_-]?string|conn[_-]?str)', re.IGNORECASE)
    }
    
    # Value patterns that look like secrets
    value_patterns = {
        'aws_access_key': re.compile(r'^AKIA[0-9A-Z]{16}$'),
        'aws_secret_key': re.compile(r'^[0-9a-zA-Z/+=]{40}$'),
        'base64_encoded': re.compile(r'^[A-Za-z0-9+/]{20,}={0,2}$'),
        'hex_string': re.compile(r'^[a-fA-F0-9]{32,}$'),
        'jwt_token': re.compile(r'^eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*$'),
        'uuid': re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.IGNORECASE)
    }
    
    for var_name, var_value in env_vars.items():
        # Check variable name patterns
        for pattern_name, pattern in secret_patterns.items():
            if pattern.search(var_name):
                potential_secrets.append({
                    'variable_name': var_name,
                    'detection_type': 'suspicious_name',
                    'pattern_matched': pattern_name,
                    'risk_level': 'HIGH',
                    'reason': f'Environment variable name "{var_name}" suggests it may contain sensitive information'
                })
                break
        
        # Check variable value patterns (if value looks like a secret)
        if var_value and len(var_value) > 10:  # Only check non-empty values with reasonable length
            for pattern_name, pattern in value_patterns.items():
                if pattern.match(var_value):
                    potential_secrets.append({
                        'variable_name': var_name,
                        'detection_type': 'suspicious_value',
                        'pattern_matched': pattern_name,
                        'risk_level': 'CRITICAL',
                        'reason': f'Environment variable "{var_name}" value matches pattern for {pattern_name}'
                    })
                    break
    
    return potential_secrets

def awslambda_function_no_secrets_in_variables_check(lambda_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for awslambda_function_no_secrets_in_variables.
    
    Args:
        lambda_client: Boto3 Lambda client (auto-created by framework)
        region (str): AWS region (auto-managed by framework)
        profile (str): AWS profile name (auto-managed by framework)
        logger: Logger instance (auto-configured by framework)
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    try:
        logger.info(f"Checking Lambda functions for secrets in environment variables in region {region}")
        
        # Get all Lambda functions
        paginator = lambda_client.get_paginator('list_functions')
        
        for page in paginator.paginate():
            functions = page.get('Functions', [])
            
            if not functions:
                continue
            
            # Check each function for secrets in environment variables
            for function in functions:
                function_name = function.get('FunctionName', 'unknown')
                function_arn = function.get('FunctionArn', 'unknown')
                runtime = function.get('Runtime', 'unknown')
                
                try:
                    # Get function configuration to access environment variables
                    config_response = lambda_client.get_function_configuration(FunctionName=function_name)
                    
                    environment = config_response.get('Environment', {})
                    env_variables = environment.get('Variables', {})
                    
                    if not env_variables:
                        # Compliant: No environment variables defined
                        finding = {
                            'region': region,
                            'profile': profile,
                            'resource_type': 'Lambda Function',
                            'resource_id': function_name,
                            'status': 'COMPLIANT',
                            'compliance_status': 'PASS',
                            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Function has no environment variables'),
                            'details': {
                                'function_name': function_name,
                                'function_arn': function_arn,
                                'runtime': runtime,
                                'environment_variables_count': 0,
                                'code_size': function.get('CodeSize', 0),
                                'last_modified': function.get('LastModified', ''),
                                'description': function.get('Description', '')
                            }
                        }
                        findings.append(finding)
                        continue
                    
                    # Check for potential secrets in environment variables
                    detected_secrets = detect_secrets_in_environment_variables(env_variables)
                    
                    if detected_secrets:
                        # Non-compliant: Potential secrets found in environment variables
                        finding = {
                            'region': region,
                            'profile': profile,
                            'resource_type': 'Lambda Function',
                            'resource_id': function_name,
                            'status': 'NON_COMPLIANT',
                            'compliance_status': 'FAIL',
                            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Move secrets to AWS Secrets Manager or Parameter Store'),
                            'details': {
                                'function_name': function_name,
                                'function_arn': function_arn,
                                'runtime': runtime,
                                'environment_variables_count': len(env_variables),
                                'issue': 'Potential secrets detected in environment variables',
                                'detected_secrets_count': len(detected_secrets),
                                'detected_secrets': detected_secrets,
                                'security_risk': 'Environment variables are stored in plaintext and accessible to anyone with function access',
                                'remediation_steps': [
                                    'Move sensitive values to AWS Secrets Manager',
                                    'Use Systems Manager Parameter Store for configuration',
                                    'Update Lambda function code to retrieve secrets at runtime',
                                    'Remove sensitive environment variables',
                                    'Use IAM roles for secure access to secret services',
                                    'Enable encryption in transit for secret retrieval'
                                ],
                                'code_size': function.get('CodeSize', 0),
                                'last_modified': function.get('LastModified', ''),
                                'description': function.get('Description', ''),
                                'all_environment_variables': list(env_variables.keys())  # Only show keys, not values
                            }
                        }
                    else:
                        # Compliant: Environment variables exist but no secrets detected
                        finding = {
                            'region': region,
                            'profile': profile,
                            'resource_type': 'Lambda Function',
                            'resource_id': function_name,
                            'status': 'COMPLIANT',
                            'compliance_status': 'PASS',
                            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Environment variables appear to be safe'),
                            'details': {
                                'function_name': function_name,
                                'function_arn': function_arn,
                                'runtime': runtime,
                                'environment_variables_count': len(env_variables),
                                'code_size': function.get('CodeSize', 0),
                                'last_modified': function.get('LastModified', ''),
                                'description': function.get('Description', ''),
                                'environment_variables': list(env_variables.keys())  # Only show keys, not values
                            }
                        }
                    
                    findings.append(finding)
                    
                except Exception as e:
                    logger.error(f"Error checking Lambda function {function_name} in {region}: {e}")
                    findings.append({
                        'region': region,
                        'profile': profile,
                        'resource_type': 'Lambda Function',
                        'resource_id': function_name,
                        'status': 'ERROR',
                        'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                        'recommendation': COMPLIANCE_DATA.get('recommendation', 'Review function configuration'),
                        'error': str(e)
                    })
        
        if not findings:
            logger.info(f"No Lambda functions found in region {region}")
        
    except Exception as e:
        logger.error(f"Error in awslambda_function_no_secrets_in_variables check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'Lambda Function',
            'status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Review and remediate as needed'),
            'error': str(e)
        })
        
    return findings

def awslambda_function_no_secrets_in_variables(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=awslambda_function_no_secrets_in_variables_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = awslambda_function_no_secrets_in_variables(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

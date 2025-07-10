#!/usr/bin/env python3
"""
iso27001_2022_aws - awslambda_function_url_cors_policy

Information stored on, processed by or accessible via user endpoint devices should be protected.
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
        'compliance_name': 'iso27001_2022_aws',
        'function_name': 'awslambda_function_url_cors_policy',
        'id': 'A.8.1.3',
        'name': 'Endpoint device protection',
        'description': 'Information stored on, processed by or accessible via user endpoint devices should be protected.',
        'api_function': 'lambda_client = boto3.client(\'lambda\'); apigatewayv2_client = boto3.client(\'apigatewayv2\')',
        'user_function': 'get_function_url_config()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Review and configure CORS policies for Lambda function URLs to prevent unauthorized cross-origin access'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('awslambda_function_url_cors_policy')

def awslambda_function_url_cors_policy_check(lambda_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for awslambda_function_url_cors_policy.
    
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
        # Get all Lambda functions
        paginator = lambda_client.get_paginator('list_functions')
        functions = []
        
        for page in paginator.paginate():
            functions.extend(page.get('Functions', []))
        
        if not functions:
            findings.append({
                'region': region,
                'profile': profile,
                'resource_type': 'Lambda Functions',
                'resource_id': 'no-functions',
                'status': 'COMPLIANT',
                'compliance_status': 'PASS',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                'recommendation': 'No Lambda functions found - no CORS policy concerns',
                'details': {
                    'functions_count': 0
                }
            })
            return findings
        
        compliant_functions = []
        non_compliant_functions = []
        functions_with_urls = []
        
        for function in functions:
            function_name = function.get('FunctionName', 'unknown')
            function_arn = function.get('FunctionArn', 'unknown')
            
            try:
                # Check if function has a function URL
                try:
                    url_config_response = lambda_client.get_function_url_config(
                        FunctionName=function_name
                    )
                    
                    has_function_url = True
                    function_url = url_config_response.get('FunctionUrl')
                    auth_type = url_config_response.get('AuthType', 'AWS_IAM')
                    cors_config = url_config_response.get('Cors', {})
                    
                except lambda_client.exceptions.ResourceNotFoundException:
                    has_function_url = False
                    function_url = None
                    auth_type = None
                    cors_config = {}
                
                function_details = {
                    'function_name': function_name,
                    'function_arn': function_arn,
                    'has_function_url': has_function_url,
                    'function_url': function_url,
                    'auth_type': auth_type,
                    'cors_config': cors_config
                }
                
                if has_function_url:
                    functions_with_urls.append(function_details)
                    
                    # Analyze CORS policy for security concerns
                    cors_issues = []
                    
                    if cors_config:
                        allow_origins = cors_config.get('AllowOrigins', [])
                        allow_methods = cors_config.get('AllowMethods', [])
                        allow_headers = cors_config.get('AllowHeaders', [])
                        expose_headers = cors_config.get('ExposeHeaders', [])
                        allow_credentials = cors_config.get('AllowCredentials', False)
                        max_age = cors_config.get('MaxAge', 0)
                        
                        # Check for overly permissive CORS settings
                        if '*' in allow_origins:
                            cors_issues.append('Wildcard (*) origin allowed - potentially insecure')
                        
                        if allow_credentials and '*' in allow_origins:
                            cors_issues.append('Credentials allowed with wildcard origin - security risk')
                        
                        if 'DELETE' in allow_methods or 'PUT' in allow_methods:
                            cors_issues.append('Destructive HTTP methods (DELETE/PUT) allowed')
                        
                        if any(header.lower() in ['authorization', 'x-api-key'] for header in allow_headers):
                            cors_issues.append('Sensitive headers allowed in CORS policy')
                        
                        if max_age > 86400:  # More than 24 hours
                            cors_issues.append(f'CORS preflight cache time too long: {max_age} seconds')
                        
                        function_details.update({
                            'cors_analysis': {
                                'allow_origins': allow_origins,
                                'allow_methods': allow_methods,
                                'allow_headers': allow_headers,
                                'expose_headers': expose_headers,
                                'allow_credentials': allow_credentials,
                                'max_age': max_age,
                                'security_issues': cors_issues
                            }
                        })
                    else:
                        # No CORS configuration might be more secure than permissive one
                        function_details['cors_analysis'] = {
                            'configured': False,
                            'note': 'No CORS configuration - browser will use default same-origin policy'
                        }
                    
                    # Determine compliance based on CORS issues and auth type
                    if cors_issues or auth_type == 'NONE':
                        non_compliant_functions.append(function_details)
                        
                        security_concerns = cors_issues.copy()
                        if auth_type == 'NONE':
                            security_concerns.append('Function URL has no authentication (NONE)')
                        
                        findings.append({
                            'region': region,
                            'profile': profile,
                            'resource_type': 'Lambda Function URL',
                            'resource_id': function_name,
                            'status': 'NON_COMPLIANT',
                            'compliance_status': 'FAIL',
                            'risk_level': 'HIGH' if auth_type == 'NONE' else COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Review CORS policy and authentication settings'),
                            'details': {
                                **function_details,
                                'security_concerns': security_concerns
                            }
                        })
                    else:
                        compliant_functions.append(function_details)
                        
                        findings.append({
                            'region': region,
                            'profile': profile,
                            'resource_type': 'Lambda Function URL',
                            'resource_id': function_name,
                            'status': 'COMPLIANT',
                            'compliance_status': 'PASS',
                            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                            'recommendation': 'Lambda function URL CORS policy is appropriately configured',
                            'details': function_details
                        })
                else:
                    # Functions without URLs are compliant for this check
                    compliant_functions.append(function_details)
                
            except Exception as e:
                logger.warning(f"Could not check function URL config for {function_name}: {e}")
                findings.append({
                    'region': region,
                    'profile': profile,
                    'resource_type': 'Lambda Function',
                    'resource_id': function_name,
                    'status': 'ERROR',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                    'recommendation': 'Review function URL configuration',
                    'details': {
                        'function_name': function_name,
                        'function_arn': function_arn,
                        'error': str(e)
                    }
                })
        
        # Add summary finding
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'Lambda Function URLs Summary',
            'resource_id': f'lambda-url-cors-{region}',
            'status': 'COMPLIANT' if not non_compliant_functions else 'NON_COMPLIANT',
            'compliance_status': 'PASS' if not non_compliant_functions else 'FAIL',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': f'Reviewed {len(functions)} Lambda functions. {len(functions_with_urls)} have function URLs.',
            'details': {
                'total_functions': len(functions),
                'functions_with_urls': len(functions_with_urls),
                'compliant_functions': len(compliant_functions),
                'non_compliant_functions': len(non_compliant_functions)
            }
        })
        
    except Exception as e:
        logger.error(f"Error in awslambda_function_url_cors_policy check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'Lambda Function URLs',
            'resource_id': f'lambda-url-cors-{region}',
            'status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Review and remediate as needed'),
            'error': str(e)
        })
        
    return findings

def awslambda_function_url_cors_policy(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=awslambda_function_url_cors_policy_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = awslambda_function_url_cors_policy(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

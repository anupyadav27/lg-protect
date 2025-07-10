#!/usr/bin/env python3
"""
kisa_isms_p_2023_korean_aws - awslambda_function_using_supported_runtimes

소프트웨어, 운영체제, 보안시스템 등의 취약점으로 인한 침해사고를 예방하기 위하여 최신 패치를 적용하여야 한다. 다만 서비스 영향을 검토하여 최신 패치 적용이 어려울 경우 별도의 보완대책을 마련하여 이행하여야 한다.
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
                    'risk_level': entry.get('Risk Level', 'HIGH'),
                    'recommendation': entry.get('Recommendation', 'Update Lambda functions to use supported runtime versions')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'kisa_isms_p_2023_korean_aws',
        'function_name': 'awslambda_function_using_supported_runtimes',
        'id': 'KISA-ISMS-P-2023-LAMBDA-RUNTIME',
        'name': 'Lambda Function Using Supported Runtimes',
        'description': '소프트웨어, 운영체제, 보안시스템 등의 취약점으로 인한 침해사고를 예방하기 위하여 최신 패치를 적용하여야 한다. 다만 서비스 영향을 검토하여 최신 패치 적용이 어려울 경우 별도의 보완대책을 마련하여 이행하여야 한다.',
        'api_function': 'client = boto3.client(\'lambda\')',
        'user_function': 'list_functions(), get_function()',
        'risk_level': 'HIGH',
        'recommendation': 'Update Lambda functions to use supported runtime versions'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('awslambda_function_using_supported_runtimes')

def awslambda_function_using_supported_runtimes_check(lambda_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Check if Lambda functions are using supported runtime versions.
    
    Args:
        lambda_client: Boto3 Lambda client
        region (str): AWS region
        profile (str): AWS profile name
        logger: Logger instance
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    # Define deprecated/unsupported runtimes based on AWS Lambda runtime deprecation schedule
    deprecated_runtimes = {
        'python2.7': 'Deprecated - Use python3.9 or later',
        'python3.6': 'Deprecated - Use python3.9 or later',
        'python3.7': 'Deprecated - Use python3.9 or later',
        'nodejs8.10': 'Deprecated - Use nodejs18.x or later',
        'nodejs10.x': 'Deprecated - Use nodejs18.x or later',
        'nodejs12.x': 'Deprecated - Use nodejs18.x or later',
        'nodejs14.x': 'Deprecated - Use nodejs18.x or later',
        'ruby2.5': 'Deprecated - Use ruby3.2 or later',
        'ruby2.7': 'Deprecated - Use ruby3.2 or later',
        'java8': 'Deprecated - Use java17 or later',
        'java8.al2': 'Use java17 or later for better support',
        'java11': 'Use java17 or later for better support',
        'go1.x': 'Deprecated - Use provided.al2 with Go 1.x or later',
        'dotnetcore2.1': 'Deprecated - Use dotnet6 or later',
        'dotnetcore3.1': 'Deprecated - Use dotnet6 or later',
        'dotnet5.0': 'Deprecated - Use dotnet6 or later'
    }
    
    # Define currently supported runtimes (as of 2024)
    supported_runtimes = {
        'python3.8', 'python3.9', 'python3.10', 'python3.11', 'python3.12',
        'nodejs16.x', 'nodejs18.x', 'nodejs20.x',
        'ruby3.2', 'ruby3.3',
        'java17', 'java21',
        'dotnet6', 'dotnet8',
        'provided', 'provided.al2', 'provided.al2023'
    }
    
    try:
        # List all Lambda functions
        paginator = lambda_client.get_paginator('list_functions')
        
        for page in paginator.paginate():
            functions = page.get('Functions', [])
            
            for function in functions:
                function_name = function.get('FunctionName', 'Unknown')
                function_arn = function.get('FunctionArn', '')
                runtime = function.get('Runtime', 'Unknown')
                last_modified = function.get('LastModified', 'Unknown')
                
                try:
                    # Get additional function details
                    function_details = lambda_client.get_function(FunctionName=function_name)
                    function_config = function_details.get('Configuration', {})
                    code_size = function_config.get('CodeSize', 0)
                    timeout = function_config.get('Timeout', 0)
                    
                    # Check if runtime is deprecated
                    if runtime in deprecated_runtimes:
                        # Function uses deprecated runtime - non-compliant
                        findings.append({
                            'region': region,
                            'profile': profile,
                            'resource_type': 'Lambda Function',
                            'resource_id': function_name,
                            'status': 'NON_COMPLIANT',
                            'compliance_status': 'FAIL',
                            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Update Lambda functions to use supported runtime versions'),
                            'details': {
                                'function_name': function_name,
                                'function_arn': function_arn,
                                'runtime': runtime,
                                'last_modified': last_modified,
                                'code_size': code_size,
                                'timeout': timeout,
                                'deprecation_reason': deprecated_runtimes[runtime],
                                'issue': f'Function uses deprecated runtime: {runtime}'
                            }
                        })
                    elif runtime in supported_runtimes:
                        # Function uses supported runtime - compliant
                        findings.append({
                            'region': region,
                            'profile': profile,
                            'resource_type': 'Lambda Function',
                            'resource_id': function_name,
                            'status': 'COMPLIANT',
                            'compliance_status': 'PASS',
                            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                            'recommendation': 'Lambda function uses supported runtime version',
                            'details': {
                                'function_name': function_name,
                                'function_arn': function_arn,
                                'runtime': runtime,
                                'last_modified': last_modified,
                                'code_size': code_size,
                                'timeout': timeout,
                                'runtime_status': 'Supported'
                            }
                        })
                    else:
                        # Unknown runtime - potentially non-compliant
                        findings.append({
                            'region': region,
                            'profile': profile,
                            'resource_type': 'Lambda Function',
                            'resource_id': function_name,
                            'status': 'NON_COMPLIANT',
                            'compliance_status': 'FAIL',
                            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                            'recommendation': 'Verify runtime support status and update if necessary',
                            'details': {
                                'function_name': function_name,
                                'function_arn': function_arn,
                                'runtime': runtime,
                                'last_modified': last_modified,
                                'code_size': code_size,
                                'timeout': timeout,
                                'issue': f'Unknown or unrecognized runtime: {runtime}',
                                'runtime_status': 'Unknown'
                            }
                        })
                        
                except Exception as function_error:
                    logger.warning(f"Error getting details for function {function_name}: {function_error}")
                    findings.append({
                        'region': region,
                        'profile': profile,
                        'resource_type': 'Lambda Function',
                        'resource_id': function_name,
                        'status': 'ERROR',
                        'compliance_status': 'ERROR',
                        'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                        'recommendation': COMPLIANCE_DATA.get('recommendation', 'Update Lambda functions to use supported runtime versions'),
                        'details': {
                            'function_name': function_name,
                            'function_arn': function_arn,
                            'runtime': runtime,
                            'error': f'Error getting function details: {str(function_error)}'
                        }
                    })
        
        # Add summary finding
        if findings:
            compliant_functions = sum(1 for finding in findings if finding.get('status') == 'COMPLIANT')
            total_functions = len(findings)
            
            findings.append({
                'region': region,
                'profile': profile,
                'resource_type': 'Lambda Runtime Summary',
                'resource_id': f'lambda-runtime-summary-{region}',
                'status': 'COMPLIANT' if compliant_functions == total_functions else 'NON_COMPLIANT',
                'compliance_status': 'PASS' if compliant_functions == total_functions else 'FAIL',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                'recommendation': 'All Lambda functions use supported runtimes' if compliant_functions == total_functions else COMPLIANCE_DATA.get('recommendation', 'Update Lambda functions to use supported runtime versions'),
                'details': {
                    'total_functions': total_functions,
                    'compliant_functions': compliant_functions,
                    'non_compliant_functions': total_functions - compliant_functions,
                    'compliance_percentage': round((compliant_functions / total_functions) * 100, 2) if total_functions > 0 else 0
                }
            })
        else:
            # No functions found
            findings.append({
                'region': region,
                'profile': profile,
                'resource_type': 'Lambda Functions',
                'resource_id': f'lambda-functions-{region}',
                'status': 'COMPLIANT',
                'compliance_status': 'PASS',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                'recommendation': 'No Lambda functions found in this region',
                'details': {
                    'function_count': 0,
                    'reason': 'No functions to evaluate'
                }
            })
        
    except Exception as e:
        logger.error(f"Error in awslambda_function_using_supported_runtimes check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'Lambda Functions',
            'resource_id': f'lambda-runtime-check-{region}',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Update Lambda functions to use supported runtime versions'),
            'error': str(e)
        })
        
    return findings

def awslambda_function_using_supported_runtimes(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=awslambda_function_using_supported_runtimes_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = awslambda_function_using_supported_runtimes(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

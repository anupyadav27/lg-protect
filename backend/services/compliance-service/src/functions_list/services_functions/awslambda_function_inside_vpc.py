#!/usr/bin/env python3
"""
iso27001_2022_aws - awslambda_function_inside_vpc

Security mechanisms, service levels and service requirements of network services should be identified, implemented and monitored.
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
        'compliance_name': 'iso27001_2022_aws',
        'function_name': 'awslambda_function_inside_vpc',
        'id': 'LM.1',
        'name': 'Lambda functions should be deployed inside a VPC',
        'description': 'Security mechanisms, service levels and service requirements of network services should be identified, implemented and monitored.',
        'api_function': 'client = boto3.client("lambda")',
        'user_function': 'list_functions(), get_function_configuration()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Deploy Lambda functions inside a VPC to enhance network security and control access to resources'
    }

COMPLIANCE_DATA = load_compliance_metadata('awslambda_function_inside_vpc')

def awslambda_function_inside_vpc_check(lambda_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for awslambda_function_inside_vpc.
    """
    findings = []
    
    try:
        # List all Lambda functions
        paginator = lambda_client.get_paginator('list_functions')
        
        for page in paginator.paginate():
            functions = page.get('Functions', [])
            
            for function in functions:
                function_name = function.get('FunctionName')
                function_arn = function.get('FunctionArn')
                runtime = function.get('Runtime', 'unknown')
                
                try:
                    # Get detailed function configuration
                    config_response = lambda_client.get_function_configuration(
                        FunctionName=function_name
                    )
                    
                    # Check VPC configuration
                    vpc_config = config_response.get('VpcConfig', {})
                    vpc_id = vpc_config.get('VpcId')
                    subnet_ids = vpc_config.get('SubnetIds', [])
                    security_group_ids = vpc_config.get('SecurityGroupIds', [])
                    
                    # Function is in VPC if it has VPC ID and subnets
                    is_in_vpc = bool(vpc_id and subnet_ids)
                    
                    status = 'COMPLIANT' if is_in_vpc else 'NON_COMPLIANT'
                    compliance_status = 'PASS' if is_in_vpc else 'FAIL'
                    
                    finding = {
                        'region': region,
                        'profile': profile,
                        'resource_type': 'LAMBDA_FUNCTION',
                        'resource_id': function_name,
                        'status': status,
                        'compliance_status': compliance_status,
                        'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                        'recommendation': COMPLIANCE_DATA.get('recommendation', 'Deploy Lambda functions inside a VPC to enhance network security and control access to resources'),
                        'details': {
                            'function_name': function_name,
                            'function_arn': function_arn,
                            'runtime': runtime,
                            'is_in_vpc': is_in_vpc,
                            'vpc_config': {
                                'vpc_id': vpc_id,
                                'subnet_ids': subnet_ids,
                                'subnet_count': len(subnet_ids),
                                'security_group_ids': security_group_ids,
                                'security_group_count': len(security_group_ids)
                            },
                            'code_size': config_response.get('CodeSize', 0),
                            'memory_size': config_response.get('MemorySize', 0),
                            'timeout': config_response.get('Timeout', 0),
                            'last_modified': config_response.get('LastModified', ''),
                            'state': config_response.get('State', 'unknown'),
                            'package_type': config_response.get('PackageType', 'Zip')
                        }
                    }
                    
                    # Add specific recommendation for non-compliant functions
                    if not is_in_vpc:
                        finding['details']['remediation_steps'] = [
                            'Navigate to Lambda console',
                            'Select the function',
                            'Go to Configuration > VPC',
                            'Edit VPC settings',
                            'Select appropriate VPC',
                            'Choose private subnets for the function',
                            'Select security groups with minimal required access',
                            'Ensure NAT Gateway or VPC endpoints for internet access if needed',
                            'Update function timeout if VPC cold start affects performance',
                            'Test function connectivity after VPC deployment'
                        ]
                        finding['details']['security_considerations'] = [
                            'Functions outside VPC have direct internet access',
                            'No network-level access controls',
                            'Cannot access VPC-only resources like RDS in private subnets',
                            'Potential for data exfiltration without network monitoring'
                        ]
                    
                except Exception as function_error:
                    logger.warning(f"Could not get configuration for function {function_name}: {function_error}")
                    finding = {
                        'region': region,
                        'profile': profile,
                        'resource_type': 'LAMBDA_FUNCTION',
                        'resource_id': function_name,
                        'status': 'ERROR',
                        'compliance_status': 'ERROR',
                        'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                        'recommendation': COMPLIANCE_DATA.get('recommendation', 'Deploy Lambda functions inside a VPC to enhance network security and control access to resources'),
                        'details': {
                            'function_name': function_name,
                            'function_arn': function_arn,
                            'runtime': runtime,
                            'error': str(function_error),
                            'reason': 'Could not retrieve function configuration'
                        }
                    }
                
                findings.append(finding)
        
        # If no functions found, add informational finding
        if not findings:
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'LAMBDA_FUNCTION',
                'resource_id': 'NO_FUNCTIONS',
                'status': 'COMPLIANT',
                'compliance_status': 'PASS',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                'recommendation': 'No Lambda functions found in this region',
                'details': {
                    'message': 'No Lambda functions found',
                    'functions_count': 0
                }
            }
            findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in awslambda_function_inside_vpc check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'LAMBDA_FUNCTION',
            'status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Deploy Lambda functions inside a VPC to enhance network security and control access to resources'),
            'error': str(e)
        })
        
    return findings

def awslambda_function_inside_vpc(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=awslambda_function_inside_vpc_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    args = setup_command_line_interface(COMPLIANCE_DATA)
    results = awslambda_function_inside_vpc(
        profile_name=args.profile,
        region_name=args.region
    )
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

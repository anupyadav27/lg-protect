#!/usr/bin/env python3
"""
iso27001_2022_aws - awslambda_function_vpc_multi_az

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
                    'recommendation': entry.get('Recommendation', 'Configure Lambda functions to use VPC with multiple AZs')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'iso27001_2022_aws',
        'function_name': 'awslambda_function_vpc_multi_az',
        'id': 'ISO27001-2022-AWS-LAMBDA-VPC-MULTI-AZ',
        'name': 'Lambda Function VPC Multi-AZ',
        'description': 'Security mechanisms, service levels and service requirements of network services should be identified, implemented and monitored.',
        'api_function': 'client = boto3.client(\'lambda\')',
        'user_function': 'list_functions(),get_function_configuration(), describe_vpcs(), describe_subnets()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Configure Lambda functions to use VPC with multiple AZs'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('awslambda_function_vpc_multi_az')

def awslambda_function_vpc_multi_az_check(lambda_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Check if Lambda functions are configured to use VPC with multiple AZs.
    
    Args:
        lambda_client: Boto3 Lambda client
        region (str): AWS region
        profile (str): AWS profile name
        logger: Logger instance
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    try:
        # Create EC2 client to check VPC and subnet details
        import boto3
        ec2_client = boto3.client('ec2', region_name=region)
        
        # List all Lambda functions
        paginator = lambda_client.get_paginator('list_functions')
        
        for page in paginator.paginate():
            functions = page.get('Functions', [])
            
            for function in functions:
                function_name = function.get('FunctionName', 'Unknown')
                function_arn = function.get('FunctionArn', '')
                runtime = function.get('Runtime', 'Unknown')
                
                try:
                    # Get function configuration
                    config_response = lambda_client.get_function_configuration(FunctionName=function_name)
                    
                    # Check VPC configuration
                    vpc_config = config_response.get('VpcConfig', {})
                    subnet_ids = vpc_config.get('SubnetIds', [])
                    security_group_ids = vpc_config.get('SecurityGroupIds', [])
                    vpc_id = vpc_config.get('VpcId')
                    
                    if not vpc_id or not subnet_ids:
                        # Function is not in VPC - compliant for this specific check (no VPC to validate)
                        findings.append({
                            'region': region,
                            'profile': profile,
                            'resource_type': 'Lambda Function',
                            'resource_id': function_name,
                            'status': 'COMPLIANT',
                            'compliance_status': 'PASS',
                            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                            'recommendation': 'Function is not in VPC - multi-AZ check not applicable',
                            'details': {
                                'function_name': function_name,
                                'function_arn': function_arn,
                                'runtime': runtime,
                                'vpc_configured': False,
                                'note': 'Function runs in AWS Lambda service VPC'
                            }
                        })
                        continue
                    
                    # Get subnet details to check availability zones
                    try:
                        subnets_response = ec2_client.describe_subnets(SubnetIds=subnet_ids)
                        subnets = subnets_response.get('Subnets', [])
                        
                        # Get unique availability zones
                        availability_zones = set()
                        subnet_details = []
                        
                        for subnet in subnets:
                            az = subnet.get('AvailabilityZone', 'Unknown')
                            availability_zones.add(az)
                            subnet_details.append({
                                'subnet_id': subnet.get('SubnetId', 'Unknown'),
                                'availability_zone': az,
                                'state': subnet.get('State', 'Unknown')
                            })
                        
                        if len(availability_zones) >= 2:
                            # Function is in VPC with multiple AZs - compliant
                            findings.append({
                                'region': region,
                                'profile': profile,
                                'resource_type': 'Lambda Function',
                                'resource_id': function_name,
                                'status': 'COMPLIANT',
                                'compliance_status': 'PASS',
                                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                                'recommendation': 'Lambda function is configured with VPC subnets across multiple AZs',
                                'details': {
                                    'function_name': function_name,
                                    'function_arn': function_arn,
                                    'runtime': runtime,
                                    'vpc_id': vpc_id,
                                    'vpc_configured': True,
                                    'subnet_count': len(subnet_ids),
                                    'availability_zone_count': len(availability_zones),
                                    'availability_zones': list(availability_zones),
                                    'subnet_details': subnet_details
                                }
                            })
                        else:
                            # Function is in VPC but only single AZ - non-compliant
                            findings.append({
                                'region': region,
                                'profile': profile,
                                'resource_type': 'Lambda Function',
                                'resource_id': function_name,
                                'status': 'NON_COMPLIANT',
                                'compliance_status': 'FAIL',
                                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                                'recommendation': COMPLIANCE_DATA.get('recommendation', 'Configure Lambda functions to use VPC with multiple AZs'),
                                'details': {
                                    'function_name': function_name,
                                    'function_arn': function_arn,
                                    'runtime': runtime,
                                    'vpc_id': vpc_id,
                                    'vpc_configured': True,
                                    'subnet_count': len(subnet_ids),
                                    'availability_zone_count': len(availability_zones),
                                    'availability_zones': list(availability_zones),
                                    'subnet_details': subnet_details,
                                    'issue': 'Function VPC configuration uses only single availability zone'
                                }
                            })
                            
                    except Exception as subnet_error:
                        logger.warning(f"Error checking subnets for function {function_name}: {subnet_error}")
                        findings.append({
                            'region': region,
                            'profile': profile,
                            'resource_type': 'Lambda Function',
                            'resource_id': function_name,
                            'status': 'ERROR',
                            'compliance_status': 'ERROR',
                            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Configure Lambda functions to use VPC with multiple AZs'),
                            'details': {
                                'function_name': function_name,
                                'function_arn': function_arn,
                                'runtime': runtime,
                                'vpc_id': vpc_id,
                                'subnet_ids': subnet_ids,
                                'error': f'Error checking subnet details: {str(subnet_error)}'
                            }
                        })
                        
                except Exception as config_error:
                    logger.warning(f"Error getting configuration for function {function_name}: {config_error}")
                    findings.append({
                        'region': region,
                        'profile': profile,
                        'resource_type': 'Lambda Function',
                        'resource_id': function_name,
                        'status': 'ERROR',
                        'compliance_status': 'ERROR',
                        'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                        'recommendation': COMPLIANCE_DATA.get('recommendation', 'Configure Lambda functions to use VPC with multiple AZs'),
                        'details': {
                            'function_name': function_name,
                            'function_arn': function_arn,
                            'error': f'Error getting function configuration: {str(config_error)}'
                        }
                    })
        
        # If no functions found
        if not findings:
            findings.append({
                'region': region,
                'profile': profile,
                'resource_type': 'Lambda Functions',
                'resource_id': f'lambda-functions-{region}',
                'status': 'COMPLIANT',
                'compliance_status': 'PASS',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                'recommendation': 'No Lambda functions found in this region',
                'details': {
                    'function_count': 0,
                    'reason': 'No functions to evaluate'
                }
            })
        
    except Exception as e:
        logger.error(f"Error in awslambda_function_vpc_multi_az check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'Lambda Functions',
            'resource_id': f'lambda-vpc-multi-az-check-{region}',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Configure Lambda functions to use VPC with multiple AZs'),
            'error': str(e)
        })
        
    return findings

def awslambda_function_vpc_multi_az(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=awslambda_function_vpc_multi_az_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = awslambda_function_vpc_multi_az(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

#!/usr/bin/env python3
"""
aws_well_architected_framework_security_pillar_aws - cloudformation_stack_outputs_find_secrets

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
                    'risk_level': entry.get('Risk Level', 'HIGH'),
                    'recommendation': entry.get('Recommendation', 'Remove secrets from CloudFormation stack outputs and use AWS Secrets Manager')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'aws_well_architected_framework_security_pillar_aws',
        'function_name': 'cloudformation_stack_outputs_find_secrets',
        'id': 'WAF-SEC-CF-SECRETS',
        'name': 'CloudFormation Stack Outputs Find Secrets',
        'description': 'A workload requires an automated capability to prove its identity to databases, resources, and third-party services. This is accomplished using secret access credentials, such as API access keys, passwords, and OAuth tokens. Using a purpose-built service to store, manage, and rotate these credentials helps reduce the likelihood that those credentials become compromised.',
        'api_function': 'client = boto3.client(\'cloudformation\')',
        'user_function': 'describe_stacks()',
        'risk_level': 'HIGH',
        'recommendation': 'Remove secrets from CloudFormation stack outputs and use AWS Secrets Manager'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('cloudformation_stack_outputs_find_secrets')

def cloudformation_stack_outputs_find_secrets_check(cloudformation_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Check CloudFormation stack outputs for potential secrets.
    
    Args:
        cloudformation_client: Boto3 CloudFormation client
        region (str): AWS region
        profile (str): AWS profile name
        logger: Logger instance
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    # Patterns that might indicate secrets in output values
    secret_patterns = [
        r'(?i)password',
        r'(?i)secret',
        r'(?i)key',
        r'(?i)token',
        r'(?i)credential',
        r'(?i)auth',
        r'(?i)api[_-]?key',
        r'(?i)access[_-]?key',
        r'(?i)private[_-]?key',
        r'[A-Za-z0-9/+=]{20,}',  # Base64-like strings
        r'AKIA[0-9A-Z]{16}',      # AWS Access Key pattern
        r'[0-9a-fA-F]{32,}',      # Hex strings (32+ chars)
    ]
    
    try:
        # Get all CloudFormation stacks
        paginator = cloudformation_client.get_paginator('describe_stacks')
        
        for page in paginator.paginate():
            stacks = page.get('Stacks', [])
            
            for stack in stacks:
                stack_name = stack.get('StackName', 'Unknown')
                stack_id = stack.get('StackId', '')
                stack_status = stack.get('StackStatus', 'Unknown')
                outputs = stack.get('Outputs', [])
                
                if not outputs:
                    # Stack has no outputs - compliant
                    continue
                
                suspicious_outputs = []
                
                for output in outputs:
                    output_key = output.get('OutputKey', '')
                    output_value = output.get('OutputValue', '')
                    output_description = output.get('Description', '')
                    
                    # Check for potential secrets in output key, value, or description
                    for pattern in secret_patterns:
                        if (re.search(pattern, output_key) or 
                            re.search(pattern, output_value) or 
                            re.search(pattern, output_description)):
                            
                            suspicious_outputs.append({
                                'output_key': output_key,
                                'output_value': output_value[:50] + '...' if len(output_value) > 50 else output_value,
                                'output_description': output_description,
                                'matched_pattern': pattern,
                                'risk_reason': f'Output matches pattern: {pattern}'
                            })
                            break  # Don't match multiple patterns for same output
                
                if suspicious_outputs:
                    # Stack has suspicious outputs - non-compliant
                    findings.append({
                        'region': region,
                        'profile': profile,
                        'resource_type': 'CloudFormation Stack',
                        'resource_id': stack_name,
                        'status': 'NON_COMPLIANT',
                        'compliance_status': 'FAIL',
                        'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                        'recommendation': COMPLIANCE_DATA.get('recommendation', 'Remove secrets from CloudFormation stack outputs and use AWS Secrets Manager'),
                        'details': {
                            'stack_name': stack_name,
                            'stack_id': stack_id,
                            'stack_status': stack_status,
                            'total_outputs': len(outputs),
                            'suspicious_outputs_count': len(suspicious_outputs),
                            'suspicious_outputs': suspicious_outputs,
                            'issue': 'Stack outputs contain potential secrets'
                        }
                    })
                else:
                    # Stack outputs look safe - compliant
                    findings.append({
                        'region': region,
                        'profile': profile,
                        'resource_type': 'CloudFormation Stack',
                        'resource_id': stack_name,
                        'status': 'COMPLIANT',
                        'compliance_status': 'PASS',
                        'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                        'recommendation': 'CloudFormation stack outputs do not contain obvious secrets',
                        'details': {
                            'stack_name': stack_name,
                            'stack_id': stack_id,
                            'stack_status': stack_status,
                            'total_outputs': len(outputs),
                            'outputs_checked': len(outputs)
                        }
                    })
        
        # If no stacks found
        if not findings:
            findings.append({
                'region': region,
                'profile': profile,
                'resource_type': 'CloudFormation Stacks',
                'resource_id': f'cloudformation-stacks-{region}',
                'status': 'COMPLIANT',
                'compliance_status': 'PASS',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                'recommendation': 'No CloudFormation stacks found in this region',
                'details': {
                    'stack_count': 0,
                    'reason': 'No stacks to evaluate'
                }
            })
        
    except Exception as e:
        logger.error(f"Error in cloudformation_stack_outputs_find_secrets check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'CloudFormation Stacks',
            'resource_id': f'cloudformation-secrets-check-{region}',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Remove secrets from CloudFormation stack outputs and use AWS Secrets Manager'),
            'error': str(e)
        })
        
    return findings

def cloudformation_stack_outputs_find_secrets(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=cloudformation_stack_outputs_find_secrets_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = cloudformation_stack_outputs_find_secrets(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

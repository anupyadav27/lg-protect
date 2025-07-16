#!/usr/bin/env python3
"""
aws_well_architected_framework_reliability_pillar_aws - cloudformation_stacks_termination_protection_enabled

Configure backups to be taken automatically based on a periodic schedule informed by the Recovery Point Objective (RPO), or by changes in the dataset. Critical datasets with low data loss requirements need to be backed up automatically on a frequent basis, whereas less critical data where some loss is acceptable can be backed up less frequently.
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
                    'recommendation': entry.get('Recommendation', 'Enable termination protection for CloudFormation stacks')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'aws_well_architected_framework_reliability_pillar_aws',
        'function_name': 'cloudformation_stacks_termination_protection_enabled',
        'id': 'WAF-REL-CF-TERM-PROT',
        'name': 'CloudFormation Stacks Termination Protection',
        'description': 'Configure backups to be taken automatically based on a periodic schedule informed by the Recovery Point Objective (RPO), or by changes in the dataset. Critical datasets with low data loss requirements need to be backed up automatically on a frequent basis, whereas less critical data where some loss is acceptable can be backed up less frequently.',
        'api_function': 'client = boto3.client(\'cloudformation\')',
        'user_function': 'describe_stacks()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Enable termination protection for CloudFormation stacks'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('cloudformation_stacks_termination_protection_enabled')

def cloudformation_stacks_termination_protection_enabled_check(cloudformation_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Check if CloudFormation stacks have termination protection enabled.
    
    Args:
        cloudformation_client: Boto3 CloudFormation client
        region (str): AWS region
        profile (str): AWS profile name
        logger: Logger instance
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    try:
        # Get all CloudFormation stacks
        paginator = cloudformation_client.get_paginator('describe_stacks')
        
        stack_count = 0
        protected_stacks = 0
        
        for page in paginator.paginate():
            stacks = page.get('Stacks', [])
            
            for stack in stacks:
                stack_name = stack.get('StackName', 'Unknown')
                stack_id = stack.get('StackId', '')
                stack_status = stack.get('StackStatus', 'Unknown')
                enable_termination_protection = stack.get('EnableTerminationProtection', False)
                creation_time = stack.get('CreationTime')
                
                stack_count += 1
                
                # Skip stacks that are being deleted or in failed states
                if 'DELETE' in stack_status or 'FAILED' in stack_status:
                    continue
                
                if enable_termination_protection:
                    # Stack has termination protection enabled - compliant
                    protected_stacks += 1
                    findings.append({
                        'region': region,
                        'profile': profile,
                        'resource_type': 'CloudFormation Stack',
                        'resource_id': stack_name,
                        'status': 'COMPLIANT',
                        'compliance_status': 'PASS',
                        'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                        'recommendation': 'CloudFormation stack has termination protection enabled',
                        'details': {
                            'stack_name': stack_name,
                            'stack_id': stack_id,
                            'stack_status': stack_status,
                            'creation_time': creation_time.isoformat() if creation_time else 'Unknown',
                            'termination_protection': enable_termination_protection
                        }
                    })
                else:
                    # Stack does not have termination protection - non-compliant
                    findings.append({
                        'region': region,
                        'profile': profile,
                        'resource_type': 'CloudFormation Stack',
                        'resource_id': stack_name,
                        'status': 'NON_COMPLIANT',
                        'compliance_status': 'FAIL',
                        'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                        'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable termination protection for CloudFormation stacks'),
                        'details': {
                            'stack_name': stack_name,
                            'stack_id': stack_id,
                            'stack_status': stack_status,
                            'creation_time': creation_time.isoformat() if creation_time else 'Unknown',
                            'termination_protection': enable_termination_protection,
                            'issue': 'Termination protection is not enabled for this stack'
                        }
                    })
        
        # Add summary finding
        if stack_count > 0:
            findings.append({
                'region': region,
                'profile': profile,
                'resource_type': 'CloudFormation Summary',
                'resource_id': f'cloudformation-termination-protection-summary-{region}',
                'status': 'COMPLIANT' if protected_stacks == stack_count else 'NON_COMPLIANT',
                'compliance_status': 'PASS' if protected_stacks == stack_count else 'FAIL',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                'recommendation': 'All CloudFormation stacks have termination protection enabled' if protected_stacks == stack_count else COMPLIANCE_DATA.get('recommendation', 'Enable termination protection for CloudFormation stacks'),
                'details': {
                    'total_stacks': stack_count,
                    'protected_stacks': protected_stacks,
                    'unprotected_stacks': stack_count - protected_stacks,
                    'protection_percentage': round((protected_stacks / stack_count) * 100, 2) if stack_count > 0 else 0
                }
            })
        else:
            # No stacks found
            findings.append({
                'region': region,
                'profile': profile,
                'resource_type': 'CloudFormation Stacks',
                'resource_id': f'cloudformation-stacks-{region}',
                'status': 'COMPLIANT',
                'compliance_status': 'PASS',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                'recommendation': 'No CloudFormation stacks found in this region',
                'details': {
                    'stack_count': 0,
                    'reason': 'No stacks to evaluate'
                }
            })
        
    except Exception as e:
        logger.error(f"Error in cloudformation_stacks_termination_protection_enabled check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'CloudFormation Stacks',
            'resource_id': f'cloudformation-termination-protection-check-{region}',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable termination protection for CloudFormation stacks'),
            'error': str(e)
        })
        
    return findings

def cloudformation_stacks_termination_protection_enabled(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=cloudformation_stacks_termination_protection_enabled_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = cloudformation_stacks_termination_protection_enabled(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

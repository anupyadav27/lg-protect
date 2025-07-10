#!/usr/bin/env python3
"""
pci_4.0_aws - autoscaling_group_launch_configuration_requires_imdsv2

Checks whether only IMDSv2 is enabled
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
        'compliance_name': 'pci_4.0_aws',
        'function_name': 'autoscaling_group_launch_configuration_requires_imdsv2',
        'id': 'PCI.AutoScaling.1',
        'name': 'Auto Scaling launch configurations should configure EC2 instances to require the use of IMDSv2',
        'description': 'Checks whether only IMDSv2 is enabled',
        'api_function': 'client = boto3.client(\'autoscaling\')',
        'user_function': 'describe_auto_scaling_groups(), describe_launch_configurations()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Configure Auto Scaling launch configurations to require IMDSv2'
    }

COMPLIANCE_DATA = load_compliance_metadata('autoscaling_group_launch_configuration_requires_imdsv2')

def autoscaling_group_launch_configuration_requires_imdsv2_check(autoscaling_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for autoscaling_group_launch_configuration_requires_imdsv2.
    """
    findings = []
    
    try:
        # Get all Auto Scaling groups
        paginator = autoscaling_client.get_paginator('describe_auto_scaling_groups')
        auto_scaling_groups = []
        
        for page in paginator.paginate():
            auto_scaling_groups.extend(page.get('AutoScalingGroups', []))
        
        if not auto_scaling_groups:
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'Auto Scaling Group',
                'resource_id': f'no-asg-{region}',
                'status': 'COMPLIANT',
                'compliance_status': 'PASS',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                'recommendation': COMPLIANCE_DATA.get('recommendation', 'Configure Auto Scaling launch configurations to require IMDSv2'),
                'details': {
                    'message': 'No Auto Scaling groups found in this region',
                    'asg_count': 0
                }
            }
            findings.append(finding)
            return findings
        
        # Get all launch configurations
        launch_configs = {}
        try:
            lc_paginator = autoscaling_client.get_paginator('describe_launch_configurations')
            for page in lc_paginator.paginate():
                for lc in page.get('LaunchConfigurations', []):
                    launch_configs[lc.get('LaunchConfigurationName')] = lc
        except Exception as e:
            logger.warning(f"Error fetching launch configurations: {e}")
        
        # Check each Auto Scaling group
        for asg in auto_scaling_groups:
            asg_name = asg.get('AutoScalingGroupName')
            asg_arn = asg.get('AutoScalingGroupARN')
            launch_config_name = asg.get('LaunchConfigurationName')
            launch_template = asg.get('LaunchTemplate')
            mixed_instances_policy = asg.get('MixedInstancesPolicy')
            
            # Skip if using launch template or mixed instances policy
            if launch_template or mixed_instances_policy:
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'Auto Scaling Group',
                    'resource_id': asg_arn or asg_name,
                    'status': 'COMPLIANT',
                    'compliance_status': 'PASS',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Configure Auto Scaling launch configurations to require IMDSv2'),
                    'details': {
                        'asg_name': asg_name,
                        'asg_arn': asg_arn,
                        'uses_launch_template': bool(launch_template),
                        'uses_mixed_instances_policy': bool(mixed_instances_policy),
                        'message': f'Auto Scaling group {asg_name} uses launch template or mixed instances policy (not launch configuration)'
                    }
                }
                findings.append(finding)
                continue
            
            # Check launch configuration if present
            if launch_config_name and launch_config_name in launch_configs:
                launch_config = launch_configs[launch_config_name]
                metadata_options = launch_config.get('MetadataOptions', {})
                http_tokens = metadata_options.get('HttpTokens', 'optional')
                
                # Check if IMDSv2 is required
                if http_tokens == 'required':
                    status = 'COMPLIANT'
                    compliance_status = 'PASS'
                    message = f'Auto Scaling group {asg_name} launch configuration requires IMDSv2'
                else:
                    status = 'NON_COMPLIANT'
                    compliance_status = 'FAIL'
                    message = f'Auto Scaling group {asg_name} launch configuration does not require IMDSv2'
                
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'Auto Scaling Group',
                    'resource_id': asg_arn or asg_name,
                    'status': status,
                    'compliance_status': compliance_status,
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Configure Auto Scaling launch configurations to require IMDSv2'),
                    'details': {
                        'asg_name': asg_name,
                        'asg_arn': asg_arn,
                        'launch_config_name': launch_config_name,
                        'http_tokens': http_tokens,
                        'imdsv2_required': http_tokens == 'required',
                        'message': message
                    }
                }
                findings.append(finding)
            else:
                # No launch configuration found
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'Auto Scaling Group',
                    'resource_id': asg_arn or asg_name,
                    'status': 'ERROR',
                    'compliance_status': 'ERROR',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Configure Auto Scaling launch configurations to require IMDSv2'),
                    'details': {
                        'asg_name': asg_name,
                        'asg_arn': asg_arn,
                        'launch_config_name': launch_config_name,
                        'message': f'Launch configuration {launch_config_name} not found for Auto Scaling group {asg_name}'
                    }
                }
                findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in autoscaling_group_launch_configuration_requires_imdsv2 check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'Auto Scaling Group',
            'resource_id': f'error-{region}',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Configure Auto Scaling launch configurations to require IMDSv2'),
            'error': str(e)
        })
        
    return findings

def autoscaling_group_launch_configuration_requires_imdsv2(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=autoscaling_group_launch_configuration_requires_imdsv2_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    args = setup_command_line_interface(COMPLIANCE_DATA)
    results = autoscaling_group_launch_configuration_requires_imdsv2(
        profile_name=args.profile,
        region_name=args.region
    )
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

#!/usr/bin/env python3
"""
iso27001_2022_aws - autoscaling_group_capacity_rebalance_enabled

Information processing facilities should be implemented with redundancy sufficient to meet availability
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
        'compliance_name': 'iso27001_2022_aws',
        'function_name': 'autoscaling_group_capacity_rebalance_enabled',
        'id': 'A.17.1.2',
        'name': 'Implementing information security continuity',
        'description': 'Information processing facilities should be implemented with redundancy sufficient to meet availability',
        'api_function': 'client = boto3.client(\'autoscaling\')',
        'user_function': 'describe_auto_scaling_groups()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Enable capacity rebalancing for Auto Scaling groups to improve availability'
    }

COMPLIANCE_DATA = load_compliance_metadata('autoscaling_group_capacity_rebalance_enabled')

def autoscaling_group_capacity_rebalance_enabled_check(autoscaling_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for autoscaling_group_capacity_rebalance_enabled.
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
                'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable capacity rebalancing for Auto Scaling groups'),
                'details': {
                    'message': 'No Auto Scaling groups found in this region',
                    'asg_count': 0
                }
            }
            findings.append(finding)
            return findings
        
        # Check each Auto Scaling group for capacity rebalancing
        for asg in auto_scaling_groups:
            asg_name = asg.get('AutoScalingGroupName')
            asg_arn = asg.get('AutoScalingGroupARN')
            capacity_rebalance = asg.get('CapacityRebalance', False)
            
            # Check if capacity rebalancing is enabled
            if capacity_rebalance:
                status = 'COMPLIANT'
                compliance_status = 'PASS'
                message = f'Auto Scaling group {asg_name} has capacity rebalancing enabled'
            else:
                status = 'NON_COMPLIANT'
                compliance_status = 'FAIL'
                message = f'Auto Scaling group {asg_name} does not have capacity rebalancing enabled'
            
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'Auto Scaling Group',
                'resource_id': asg_arn or asg_name,
                'status': status,
                'compliance_status': compliance_status,
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable capacity rebalancing for Auto Scaling groups'),
                'details': {
                    'asg_name': asg_name,
                    'asg_arn': asg_arn,
                    'capacity_rebalance': capacity_rebalance,
                    'min_size': asg.get('MinSize'),
                    'max_size': asg.get('MaxSize'),
                    'desired_capacity': asg.get('DesiredCapacity'),
                    'availability_zones': asg.get('AvailabilityZones', []),
                    'vpc_zone_identifier': asg.get('VPCZoneIdentifier'),
                    'health_check_type': asg.get('HealthCheckType'),
                    'message': message
                }
            }
            findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in autoscaling_group_capacity_rebalance_enabled check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'Auto Scaling Group',
            'resource_id': f'error-{region}',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable capacity rebalancing for Auto Scaling groups'),
            'error': str(e)
        })
        
    return findings

def autoscaling_group_capacity_rebalance_enabled(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=autoscaling_group_capacity_rebalance_enabled_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    args = setup_command_line_interface(COMPLIANCE_DATA)
    results = autoscaling_group_capacity_rebalance_enabled(
        profile_name=args.profile,
        region_name=args.region
    )
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

#!/usr/bin/env python3
"""
iso27001_2022_aws - autoscaling_group_multiple_az

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
        'function_name': 'autoscaling_group_multiple_az',
        'id': 'A.17.1.2',
        'name': 'Implementing information security continuity',
        'description': 'Information processing facilities should be implemented with redundancy sufficient to meet availability',
        'api_function': 'client = boto3.client(\'autoscaling\')',
        'user_function': 'describe_auto_scaling_groups()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Configure Auto Scaling groups to span multiple Availability Zones'
    }

COMPLIANCE_DATA = load_compliance_metadata('autoscaling_group_multiple_az')

def autoscaling_group_multiple_az_check(autoscaling_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for autoscaling_group_multiple_az.
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
                'recommendation': COMPLIANCE_DATA.get('recommendation', 'Configure Auto Scaling groups to span multiple Availability Zones'),
                'details': {
                    'message': 'No Auto Scaling groups found in this region',
                    'asg_count': 0
                }
            }
            findings.append(finding)
            return findings
        
        # Check each Auto Scaling group for multiple AZ configuration
        for asg in auto_scaling_groups:
            asg_name = asg.get('AutoScalingGroupName')
            asg_arn = asg.get('AutoScalingGroupARN')
            availability_zones = asg.get('AvailabilityZones', [])
            vpc_zone_identifier = asg.get('VPCZoneIdentifier', '')
            min_size = asg.get('MinSize', 0)
            max_size = asg.get('MaxSize', 0)
            desired_capacity = asg.get('DesiredCapacity', 0)
            
            # Check if ASG spans multiple AZs
            az_count = len(availability_zones)
            subnet_count = len(vpc_zone_identifier.split(',')) if vpc_zone_identifier else 0
            
            if az_count >= 2:
                status = 'COMPLIANT'
                compliance_status = 'PASS'
                message = f'Auto Scaling group {asg_name} spans {az_count} Availability Zones'
            else:
                status = 'NON_COMPLIANT'
                compliance_status = 'FAIL'
                message = f'Auto Scaling group {asg_name} only spans {az_count} Availability Zone(s)'
            
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'Auto Scaling Group',
                'resource_id': asg_arn or asg_name,
                'status': status,
                'compliance_status': compliance_status,
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                'recommendation': COMPLIANCE_DATA.get('recommendation', 'Configure Auto Scaling groups to span multiple Availability Zones'),
                'details': {
                    'asg_name': asg_name,
                    'asg_arn': asg_arn,
                    'availability_zones': availability_zones,
                    'az_count': az_count,
                    'subnet_count': subnet_count,
                    'min_size': min_size,
                    'max_size': max_size,
                    'desired_capacity': desired_capacity,
                    'vpc_zone_identifier': vpc_zone_identifier,
                    'health_check_type': asg.get('HealthCheckType'),
                    'health_check_grace_period': asg.get('HealthCheckGracePeriod'),
                    'default_cooldown': asg.get('DefaultCooldown'),
                    'multiple_az': az_count >= 2,
                    'message': message
                }
            }
            findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in autoscaling_group_multiple_az check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'Auto Scaling Group',
            'resource_id': f'error-{region}',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Configure Auto Scaling groups to span multiple Availability Zones'),
            'error': str(e)
        })
        
    return findings

def autoscaling_group_multiple_az(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=autoscaling_group_multiple_az_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    args = setup_command_line_interface(COMPLIANCE_DATA)
    results = autoscaling_group_multiple_az(
        profile_name=args.profile,
        region_name=args.region
    )
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

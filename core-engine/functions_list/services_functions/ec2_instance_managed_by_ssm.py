#!/usr/bin/env python3
"""
iso27001_2022_aws - ec2_instance_managed_by_ssm

Systems should be regularly monitored to detect deviation from the information security policy.
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
                    'recommendation': entry.get('Recommendation', 'Configure EC2 instances to be managed by AWS Systems Manager for better monitoring and compliance')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    return {
        'compliance_name': 'iso27001_2022_aws',
        'function_name': 'ec2_instance_managed_by_ssm',
        'id': 'ISO-27001-2022-A.12.1',
        'name': 'Systems Management and Monitoring',
        'description': 'Systems should be regularly monitored to detect deviation from the information security policy.',
        'api_function': 'client1=boto3.client(\'ec2\'), client2=boto3.client(\'ssm\')',
        'user_function': 'describe_instances(), describe_instance_information()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Configure EC2 instances to be managed by AWS Systems Manager for better monitoring and compliance'
    }

COMPLIANCE_DATA = load_compliance_metadata('ec2_instance_managed_by_ssm')

def ec2_instance_managed_by_ssm_check(ec2_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for ec2_instance_managed_by_ssm.
    
    Note: This function requires both EC2 and SSM clients. The compliance engine
    automatically detects the need for SSM client based on the function logic.
    """
    findings = []
    
    try:
        # Create SSM client for this check
        import boto3
        from compliance_engine.aws_session_manager import AWSSessionManager
        
        session_manager = AWSSessionManager()
        session = session_manager.get_session(profile)
        ssm_client = session.client('ssm', region_name=region)
        
        # Get all EC2 instances
        ec2_response = ec2_client.describe_instances()
        reservations = ec2_response.get('Reservations', [])
        
        all_instances = []
        for reservation in reservations:
            all_instances.extend(reservation.get('Instances', []))
        
        if not all_instances:
            finding = {
                'region': region, 'profile': profile, 'resource_type': 'EC2Instance',
                'resource_id': f'no-ec2-instances-{region}', 'status': 'COMPLIANT',
                'compliance_status': 'PASS', 'risk_level': 'LOW',
                'recommendation': 'No EC2 instances found in this region',
                'details': {'instances_count': 0, 'message': 'No EC2 instances found to check for SSM management'}
            }
            findings.append(finding)
            return findings
        
        # Get SSM managed instances
        try:
            ssm_response = ssm_client.describe_instance_information()
            ssm_managed_instances = set()
            
            for instance_info in ssm_response.get('InstanceInformationList', []):
                instance_id = instance_info.get('InstanceId')
                ping_status = instance_info.get('PingStatus', 'Unknown')
                if instance_id and ping_status in ['Online', 'ConnectionLost']:
                    ssm_managed_instances.add(instance_id)
            
            # Handle pagination for SSM
            while 'NextToken' in ssm_response:
                ssm_response = ssm_client.describe_instance_information(
                    NextToken=ssm_response['NextToken']
                )
                for instance_info in ssm_response.get('InstanceInformationList', []):
                    instance_id = instance_info.get('InstanceId')
                    ping_status = instance_info.get('PingStatus', 'Unknown')
                    if instance_id and ping_status in ['Online', 'ConnectionLost']:
                        ssm_managed_instances.add(instance_id)
                        
        except Exception as ssm_error:
            logger.warning(f"Error getting SSM managed instances: {ssm_error}")
            ssm_managed_instances = set()
        
        # Check each EC2 instance
        unmanaged_count = 0
        instances_checked = 0
        
        for instance in all_instances:
            instance_id = instance.get('InstanceId', 'unknown')
            instance_state = instance.get('State', {}).get('Name', 'unknown')
            instance_type = instance.get('InstanceType', 'unknown')
            platform = instance.get('Platform', 'linux')
            
            # Skip terminated instances
            if instance_state in ['terminated', 'shutting-down']:
                continue
            
            instances_checked += 1
            
            # Check if instance is managed by SSM
            is_ssm_managed = instance_id in ssm_managed_instances
            
            # Determine compliance status
            if is_ssm_managed:
                status = 'COMPLIANT'
                compliance_status = 'PASS'
                risk_level = 'LOW'
                recommendation = 'EC2 instance is properly managed by AWS Systems Manager'
            else:
                unmanaged_count += 1
                status = 'NON_COMPLIANT'
                compliance_status = 'FAIL'
                risk_level = COMPLIANCE_DATA.get('risk_level', 'MEDIUM')
                recommendation = COMPLIANCE_DATA.get('recommendation', 'Configure EC2 instance to be managed by AWS Systems Manager')
            
            # Check if instance has SSM agent prerequisites
            has_iam_role = bool(instance.get('IamInstanceProfile'))
            is_in_vpc = bool(instance.get('VpcId'))
            
            finding = {
                'region': region, 'profile': profile, 'resource_type': 'EC2Instance',
                'resource_id': instance_id, 'status': status, 'compliance_status': compliance_status,
                'risk_level': risk_level, 'recommendation': recommendation,
                'details': {
                    'instance_id': instance_id, 'instance_state': instance_state, 'instance_type': instance_type,
                    'is_ssm_managed': is_ssm_managed, 'has_iam_instance_profile': has_iam_role,
                    'is_in_vpc': is_in_vpc, 'platform': platform,
                    'availability_zone': instance.get('Placement', {}).get('AvailabilityZone', 'unknown'),
                    'vpc_id': instance.get('VpcId', 'unknown'),
                    'subnet_id': instance.get('SubnetId', 'unknown'),
                    'launch_time': instance.get('LaunchTime', '').isoformat() if instance.get('LaunchTime') else None,
                    'tags': instance.get('Tags', []),
                    'security_note': 'SSM management enables patch management, configuration compliance, and remote access',
                    'prerequisites_note': 'SSM agent requires IAM instance profile with appropriate permissions'
                }
            }
            findings.append(finding)
        
        logger.info(f"Checked {instances_checked} active EC2 instances, found {unmanaged_count} not managed by SSM")
        
    except Exception as e:
        logger.error(f"Error in ec2_instance_managed_by_ssm check for {region}: {e}")
        findings.append({
            'region': region, 'profile': profile, 'resource_type': 'EC2Instance',
            'resource_id': f'error-check-{region}', 'status': 'ERROR', 'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Configure EC2 instances to be managed by SSM'),
            'error': str(e)
        })
        
    return findings

def ec2_instance_managed_by_ssm(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=ec2_instance_managed_by_ssm_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    args = setup_command_line_interface(COMPLIANCE_DATA)
    results = ec2_instance_managed_by_ssm(
        profile_name=args.profile, region_name=args.region
    )
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

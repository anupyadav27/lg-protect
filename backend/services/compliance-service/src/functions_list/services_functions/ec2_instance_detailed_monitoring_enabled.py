#!/usr/bin/env python3
"""
iso27001_2022_aws - ec2_instance_detailed_monitoring_enabled

Logs that record activities, exceptions, faults and other relevant events should be produced, stored, protected and analysed.
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
                    'recommendation': entry.get('Recommendation', 'Enable detailed monitoring for EC2 instances to improve observability')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    return {
        'compliance_name': 'pci_4.0_aws',
        'function_name': 'ec2_instance_detailed_monitoring_enabled',
        'id': 'PCI-DSS-4.0-10.3',
        'name': 'System Monitoring',
        'description': 'Logs that record activities, exceptions, faults and other relevant events should be produced, stored, protected and analysed.',
        'api_function': 'client=boto3.client(\'ec2\')',
        'user_function': 'describe_instances()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Enable detailed monitoring for EC2 instances to improve observability'
    }

COMPLIANCE_DATA = load_compliance_metadata('ec2_instance_detailed_monitoring_enabled')

def ec2_instance_detailed_monitoring_enabled_check(ec2_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """Perform the actual compliance check for ec2_instance_detailed_monitoring_enabled."""
    findings = []
    
    try:
        response = ec2_client.describe_instances()
        reservations = response.get('Reservations', [])
        
        all_instances = []
        for reservation in reservations:
            all_instances.extend(reservation.get('Instances', []))
        
        if not all_instances:
            finding = {
                'region': region, 'profile': profile, 'resource_type': 'EC2Instance',
                'resource_id': f'no-ec2-instances-{region}', 'status': 'COMPLIANT',
                'compliance_status': 'PASS', 'risk_level': 'LOW',
                'recommendation': 'No EC2 instances found in this region',
                'details': {'instances_count': 0, 'message': 'No EC2 instances found to check for detailed monitoring'}
            }
            findings.append(finding)
            return findings
        
        instances_without_monitoring = 0
        instances_checked = 0
        
        for instance in all_instances:
            instance_id = instance.get('InstanceId', 'unknown')
            instance_state = instance.get('State', {}).get('Name', 'unknown')
            instance_type = instance.get('InstanceType', 'unknown')
            
            if instance_state in ['terminated', 'shutting-down']:
                continue
            
            instances_checked += 1
            
            # Check detailed monitoring status
            monitoring = instance.get('Monitoring', {})
            monitoring_state = monitoring.get('State', 'disabled')
            has_detailed_monitoring = (monitoring_state == 'enabled')
            
            if has_detailed_monitoring:
                status = 'COMPLIANT'
                compliance_status = 'PASS'
                risk_level = 'LOW'
                recommendation = 'EC2 instance has detailed monitoring enabled'
            else:
                instances_without_monitoring += 1
                status = 'NON_COMPLIANT'
                compliance_status = 'FAIL'
                risk_level = COMPLIANCE_DATA.get('risk_level', 'MEDIUM')
                recommendation = COMPLIANCE_DATA.get('recommendation', 'Enable detailed monitoring for EC2 instance')
            
            finding = {
                'region': region, 'profile': profile, 'resource_type': 'EC2Instance',
                'resource_id': instance_id, 'status': status, 'compliance_status': compliance_status,
                'risk_level': risk_level, 'recommendation': recommendation,
                'details': {
                    'instance_id': instance_id, 'instance_state': instance_state, 'instance_type': instance_type,
                    'detailed_monitoring_enabled': has_detailed_monitoring, 'monitoring_state': monitoring_state,
                    'availability_zone': instance.get('Placement', {}).get('AvailabilityZone', 'unknown'),
                    'vpc_id': instance.get('VpcId', 'unknown'),
                    'launch_time': instance.get('LaunchTime', '').isoformat() if instance.get('LaunchTime') else None,
                    'tags': instance.get('Tags', []),
                    'security_note': 'Detailed monitoring provides 1-minute CloudWatch metrics for better observability'
                }
            }
            findings.append(finding)
        
        logger.info(f"Checked {instances_checked} active EC2 instances, found {instances_without_monitoring} without detailed monitoring")
        
    except Exception as e:
        logger.error(f"Error in ec2_instance_detailed_monitoring_enabled check for {region}: {e}")
        findings.append({
            'region': region, 'profile': profile, 'resource_type': 'EC2Instance',
            'resource_id': f'error-check-{region}', 'status': 'ERROR', 'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable detailed monitoring for EC2 instances'),
            'error': str(e)
        })
        
    return findings

def ec2_instance_detailed_monitoring_enabled(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=ec2_instance_detailed_monitoring_enabled_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    args = setup_command_line_interface(COMPLIANCE_DATA)
    results = ec2_instance_detailed_monitoring_enabled(
        profile_name=args.profile, region_name=args.region
    )
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

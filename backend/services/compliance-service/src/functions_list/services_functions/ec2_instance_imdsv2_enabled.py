#!/usr/bin/env python3
"""
cis_4.0_aws - ec2_instance_imdsv2_enabled

Ensure that the EC2 Metadata Service only allows IMDSv2
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
                    'risk_level': entry.get('Risk Level', 'HIGH'),
                    'recommendation': entry.get('Recommendation', 'Enable IMDSv2 only and disable IMDSv1 on all EC2 instances')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    return {
        'compliance_name': 'cis_4.0_aws',
        'function_name': 'ec2_instance_imdsv2_enabled',
        'id': 'CIS-4.0-2.2.1',
        'name': 'EC2 Metadata Service v2 Enforcement',
        'description': 'Ensure that the EC2 Metadata Service only allows IMDSv2',
        'api_function': 'ec2 = boto3.client(\'ec2\')',
        'user_function': 'describe_instances()',
        'risk_level': 'HIGH',
        'recommendation': 'Enable IMDSv2 only and disable IMDSv1 on all EC2 instances'
    }

COMPLIANCE_DATA = load_compliance_metadata('ec2_instance_imdsv2_enabled')

def analyze_imds_configuration(instance: Dict[str, Any]) -> Dict[str, Any]:
    """Analyze the Instance Metadata Service configuration for an EC2 instance."""
    metadata_options = instance.get('MetadataOptions', {})
    
    # Extract IMDS configuration
    http_tokens = metadata_options.get('HttpTokens', 'optional')  # required = IMDSv2 only
    http_put_response_hop_limit = metadata_options.get('HttpPutResponseHopLimit', 1)
    http_endpoint = metadata_options.get('HttpEndpoint', 'enabled')
    http_protocol_ipv6 = metadata_options.get('HttpProtocolIpv6', 'disabled')
    instance_metadata_tags = metadata_options.get('InstanceMetadataTags', 'disabled')
    
    # Determine compliance status
    is_imdsv2_enforced = http_tokens == 'required'
    is_endpoint_enabled = http_endpoint == 'enabled'
    
    # Security assessment
    if not is_endpoint_enabled:
        security_status = 'SECURE_DISABLED'
        compliance_status = 'COMPLIANT'
        risk_assessment = 'IMDS completely disabled - most secure configuration'
    elif is_imdsv2_enforced:
        security_status = 'SECURE_IMDSV2'
        compliance_status = 'COMPLIANT'
        risk_assessment = 'IMDSv2 enforced - secure configuration'
    else:
        security_status = 'INSECURE_IMDSV1'
        compliance_status = 'NON_COMPLIANT'
        risk_assessment = 'IMDSv1 allowed - vulnerable to SSRF attacks'
    
    return {
        'http_tokens': http_tokens,
        'http_endpoint': http_endpoint,
        'http_put_response_hop_limit': http_put_response_hop_limit,
        'http_protocol_ipv6': http_protocol_ipv6,
        'instance_metadata_tags': instance_metadata_tags,
        'is_imdsv2_enforced': is_imdsv2_enforced,
        'is_endpoint_enabled': is_endpoint_enabled,
        'security_status': security_status,
        'compliance_status': compliance_status,
        'risk_assessment': risk_assessment,
        'imds_version_allowed': 'v2 only' if is_imdsv2_enforced else 'v1 and v2' if is_endpoint_enabled else 'disabled'
    }

def ec2_instance_imdsv2_enabled_check(ec2_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """Perform the actual compliance check for ec2_instance_imdsv2_enabled."""
    findings = []
    
    try:
        # Get all EC2 instances
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
                'details': {'instances_count': 0, 'message': 'No EC2 instances found to check IMDS configuration'}
            }
            findings.append(finding)
            return findings
        
        # Check each instance
        non_compliant_instances = 0
        instances_checked = 0
        
        for instance in all_instances:
            instance_id = instance.get('InstanceId', 'unknown')
            instance_state = instance.get('State', {}).get('Name', 'unknown')
            instance_type = instance.get('InstanceType', 'unknown')
            
            # Skip terminated instances
            if instance_state in ['terminated', 'shutting-down']:
                continue
            
            instances_checked += 1
            
            # Analyze IMDS configuration
            imds_analysis = analyze_imds_configuration(instance)
            
            # Determine overall compliance
            if imds_analysis['compliance_status'] == 'COMPLIANT':
                status = 'COMPLIANT'
                compliance_status = 'PASS'
                risk_level = 'LOW'
                recommendation = f"Instance has secure IMDS configuration: {imds_analysis['risk_assessment']}"
            else:
                non_compliant_instances += 1
                status = 'NON_COMPLIANT'
                compliance_status = 'FAIL'
                risk_level = COMPLIANCE_DATA.get('risk_level', 'HIGH')
                recommendation = COMPLIANCE_DATA.get('recommendation', 'Enable IMDSv2 only')
            
            # Get instance tags and other metadata
            tags = {tag.get('Key', ''): tag.get('Value', '') for tag in instance.get('Tags', [])}
            
            finding = {
                'region': region, 'profile': profile, 'resource_type': 'EC2Instance',
                'resource_id': instance_id, 'status': status, 'compliance_status': compliance_status,
                'risk_level': risk_level, 'recommendation': recommendation,
                'details': {
                    'instance_id': instance_id, 'instance_state': instance_state, 'instance_type': instance_type,
                    'imds_http_tokens': imds_analysis['http_tokens'],
                    'imds_endpoint': imds_analysis['http_endpoint'],
                    'imds_hop_limit': imds_analysis['http_put_response_hop_limit'],
                    'imds_ipv6_enabled': imds_analysis['http_protocol_ipv6'],
                    'instance_metadata_tags': imds_analysis['instance_metadata_tags'],
                    'is_imdsv2_enforced': imds_analysis['is_imdsv2_enforced'],
                    'imds_version_allowed': imds_analysis['imds_version_allowed'],
                    'security_status': imds_analysis['security_status'],
                    'risk_assessment': imds_analysis['risk_assessment'],
                    'platform': instance.get('Platform', 'linux'),
                    'availability_zone': instance.get('Placement', {}).get('AvailabilityZone', 'unknown'),
                    'vpc_id': instance.get('VpcId', 'unknown'),
                    'subnet_id': instance.get('SubnetId', 'unknown'),
                    'tags': tags,
                    'security_note': 'IMDSv1 is vulnerable to Server-Side Request Forgery (SSRF) attacks',
                    'mitigation_note': 'Use aws ec2 modify-instance-metadata-options to enforce IMDSv2'
                }
            }
            findings.append(finding)
        
        logger.info(f"Checked {instances_checked} active EC2 instances, found {non_compliant_instances} without IMDSv2 enforcement")
        
    except Exception as e:
        logger.error(f"Error in ec2_instance_imdsv2_enabled check for {region}: {e}")
        findings.append({
            'region': region, 'profile': profile, 'resource_type': 'EC2Instance',
            'resource_id': f'error-check-{region}', 'status': 'ERROR', 'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable IMDSv2 only'),
            'error': str(e)
        })
        
    return findings

def ec2_instance_imdsv2_enabled(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=ec2_instance_imdsv2_enabled_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    args = setup_command_line_interface(COMPLIANCE_DATA)
    results = ec2_instance_imdsv2_enabled(
        profile_name=args.profile, region_name=args.region
    )
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

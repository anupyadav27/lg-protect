#!/usr/bin/env python3
"""
iso27001_2022_aws - ec2_instance_account_imdsv2_enabled

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
                    'risk_level': entry.get('Risk Level', 'HIGH'),
                    'recommendation': entry.get('Recommendation', 'Enable IMDSv2 enforcement at account level for all EC2 instances')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'iso27001_2022_aws',
        'function_name': 'ec2_instance_account_imdsv2_enabled',
        'id': 'ISO-27001-2022-A.13.1',
        'name': 'Instance Metadata Service Security',
        'description': 'Security mechanisms, service levels and service requirements of network services should be identified, implemented and monitored.',
        'api_function': 'client=boto3.client(\'ec2\')',
        'user_function': 'describe_instances()',
        'risk_level': 'HIGH',
        'recommendation': 'Enable IMDSv2 enforcement at account level for all EC2 instances'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('ec2_instance_account_imdsv2_enabled')

def check_instance_imdsv2_configuration(instance: Dict[str, Any]) -> Dict[str, Any]:
    """
    Check EC2 instance IMDSv2 configuration.
    
    Args:
        instance: EC2 instance configuration
        
    Returns:
        IMDSv2 configuration analysis
    """
    metadata_options = instance.get('MetadataOptions', {})
    
    analysis = {
        'imds_enabled': True,
        'imdsv2_required': False,
        'imds_hop_limit': 1,
        'imds_tokens': 'optional',
        'imds_endpoint': 'enabled',
        'is_compliant': False,
        'configuration_details': metadata_options
    }
    
    if metadata_options:
        # Check if IMDS is enabled
        http_endpoint = metadata_options.get('HttpEndpoint', 'enabled')
        analysis['imds_endpoint'] = http_endpoint
        analysis['imds_enabled'] = (http_endpoint == 'enabled')
        
        # Check if IMDSv2 is required
        http_tokens = metadata_options.get('HttpTokens', 'optional')
        analysis['imds_tokens'] = http_tokens
        analysis['imdsv2_required'] = (http_tokens == 'required')
        
        # Check hop limit
        hop_limit = metadata_options.get('HttpPutResponseHopLimit', 1)
        analysis['imds_hop_limit'] = hop_limit
        
        # Determine compliance
        # Compliant if IMDSv2 is required OR IMDS is disabled
        analysis['is_compliant'] = (http_tokens == 'required') or (http_endpoint == 'disabled')
    
    return analysis

def ec2_instance_account_imdsv2_enabled_check(ec2_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for ec2_instance_account_imdsv2_enabled.
    
    Args:
        ec2_client: Boto3 EC2 client (auto-created by framework)
        region (str): AWS region (auto-managed by framework)
        profile (str): AWS profile name (auto-managed by framework)
        logger: Logger instance (auto-configured by framework)
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    try:
        # Get all EC2 instances
        response = ec2_client.describe_instances()
        reservations = response.get('Reservations', [])
        
        all_instances = []
        for reservation in reservations:
            all_instances.extend(reservation.get('Instances', []))
        
        if not all_instances:
            # No EC2 instances found
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'EC2Instance',
                'resource_id': f'no-ec2-instances-{region}',
                'status': 'COMPLIANT',
                'compliance_status': 'PASS',
                'risk_level': 'LOW',
                'recommendation': 'No EC2 instances found in this region',
                'details': {
                    'instances_count': 0,
                    'message': 'No EC2 instances found to check for IMDSv2 configuration'
                }
            }
            findings.append(finding)
            return findings
        
        # Check each instance for IMDSv2 configuration
        non_compliant_count = 0
        instances_checked = 0
        
        for instance in all_instances:
            instance_id = instance.get('InstanceId', 'unknown')
            instance_state = instance.get('State', {}).get('Name', 'unknown')
            instance_type = instance.get('InstanceType', 'unknown')
            
            # Skip terminated instances
            if instance_state in ['terminated', 'shutting-down']:
                continue
            
            instances_checked += 1
            
            # Check IMDSv2 configuration
            imds_analysis = check_instance_imdsv2_configuration(instance)
            
            if imds_analysis['is_compliant']:
                status = 'COMPLIANT'
                compliance_status = 'PASS'
                risk_level = 'LOW'
                if imds_analysis['imdsv2_required']:
                    recommendation = 'EC2 instance has IMDSv2 properly enforced'
                else:
                    recommendation = 'EC2 instance has IMDS disabled (secure configuration)'
            else:
                non_compliant_count += 1
                status = 'NON_COMPLIANT'
                compliance_status = 'FAIL'
                risk_level = COMPLIANCE_DATA.get('risk_level', 'HIGH')
                recommendation = COMPLIANCE_DATA.get('recommendation', 'Enable IMDSv2 requirement for this EC2 instance')
            
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'EC2Instance',
                'resource_id': instance_id,
                'status': status,
                'compliance_status': compliance_status,
                'risk_level': risk_level,
                'recommendation': recommendation,
                'details': {
                    'instance_id': instance_id,
                    'instance_state': instance_state,
                    'instance_type': instance_type,
                    'imds_enabled': imds_analysis['imds_enabled'],
                    'imdsv2_required': imds_analysis['imdsv2_required'],
                    'imds_tokens': imds_analysis['imds_tokens'],
                    'imds_endpoint': imds_analysis['imds_endpoint'],
                    'imds_hop_limit': imds_analysis['imds_hop_limit'],
                    'is_compliant': imds_analysis['is_compliant'],
                    'metadata_options': imds_analysis['configuration_details'],
                    'availability_zone': instance.get('Placement', {}).get('AvailabilityZone', 'unknown'),
                    'vpc_id': instance.get('VpcId', 'unknown'),
                    'launch_time': instance.get('LaunchTime', '').isoformat() if instance.get('LaunchTime') else None,
                    'public_ip_address': instance.get('PublicIpAddress'),
                    'tags': instance.get('Tags', []),
                    'security_note': 'IMDSv2 provides enhanced security by requiring session tokens for metadata access',
                    'remediation_note': 'IMDSv2 can be enforced using modify-instance-metadata-options API'
                }
            }
            
            findings.append(finding)
        
        logger.info(f"Checked {instances_checked} active EC2 instances, found {non_compliant_count} without IMDSv2 enforcement")
        
    except Exception as e:
        logger.error(f"Error in ec2_instance_account_imdsv2_enabled check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'EC2Instance',
            'resource_id': f'error-check-{region}',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable IMDSv2 enforcement for EC2 instances'),
            'error': str(e)
        })
        
    return findings

def ec2_instance_account_imdsv2_enabled(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=ec2_instance_account_imdsv2_enabled_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = ec2_instance_account_imdsv2_enabled(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

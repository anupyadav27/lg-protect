#!/usr/bin/env python3
"""
iso27001_2022_aws - vpc_subnet_no_public_ip_by_default

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
        'function_name': 'vpc_subnet_no_public_ip_by_default',
        'id': 'EC2.15',
        'name': 'VPC subnet should not assign public IP by default',
        'description': 'Security mechanisms, service levels and service requirements of network services should be identified, implemented and monitored.',
        'api_function': 'client = boto3.client("ec2")',
        'user_function': 'describe_subnets()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Disable automatic public IP assignment for VPC subnets'
    }

COMPLIANCE_DATA = load_compliance_metadata('vpc_subnet_no_public_ip_by_default')

def vpc_subnet_no_public_ip_by_default_check(ec2_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for vpc_subnet_no_public_ip_by_default.
    
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
        # Get all subnets in the region
        response = ec2_client.describe_subnets()
        subnets = response.get('Subnets', [])
        
        for subnet in subnets:
            subnet_id = subnet.get('SubnetId')
            vpc_id = subnet.get('VpcId')
            availability_zone = subnet.get('AvailabilityZone')
            map_public_ip_on_launch = subnet.get('MapPublicIpOnLaunch', False)
            
            # Check if subnet assigns public IP by default
            assigns_public_ip = map_public_ip_on_launch
            
            status = 'NON_COMPLIANT' if assigns_public_ip else 'COMPLIANT'
            compliance_status = 'FAIL' if assigns_public_ip else 'PASS'
            
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'VPC_SUBNET',
                'resource_id': subnet_id,
                'status': status,
                'compliance_status': compliance_status,
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                'recommendation': COMPLIANCE_DATA.get('recommendation', 'Disable automatic public IP assignment for VPC subnets'),
                'details': {
                    'subnet_id': subnet_id,
                    'vpc_id': vpc_id,
                    'availability_zone': availability_zone,
                    'map_public_ip_on_launch': map_public_ip_on_launch,
                    'assigns_public_ip_by_default': assigns_public_ip,
                    'cidr_block': subnet.get('CidrBlock'),
                    'state': subnet.get('State')
                }
            }
            
            findings.append(finding)
        
        # If no subnets found, add informational finding
        if not subnets:
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'VPC_SUBNET',
                'resource_id': 'NO_SUBNETS',
                'status': 'COMPLIANT',
                'compliance_status': 'PASS',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                'recommendation': 'No VPC subnets found in this region',
                'details': {
                    'message': 'No VPC subnets found',
                    'subnets_count': 0
                }
            }
            findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in vpc_subnet_no_public_ip_by_default check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'VPC_SUBNET',
            'status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Disable automatic public IP assignment for VPC subnets'),
            'error': str(e)
        })
        
    return findings

def vpc_subnet_no_public_ip_by_default(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=vpc_subnet_no_public_ip_by_default_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    args = setup_command_line_interface(COMPLIANCE_DATA)
    results = vpc_subnet_no_public_ip_by_default(
        profile_name=args.profile,
        region_name=args.region
    )
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

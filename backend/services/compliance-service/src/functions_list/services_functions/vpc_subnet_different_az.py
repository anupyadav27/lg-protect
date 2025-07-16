#!/usr/bin/env python3
"""
iso27001_2022_aws - vpc_subnet_different_az

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
        'function_name': 'vpc_subnet_different_az',
        'id': 'EC2.X',
        'name': 'VPC subnets should be in different availability zones',
        'description': 'Security mechanisms, service levels and service requirements of network services should be identified, implemented and monitored.',
        'api_function': 'client = boto3.client("ec2")',
        'user_function': 'describe_subnets()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Distribute VPC subnets across multiple availability zones for high availability'
    }

COMPLIANCE_DATA = load_compliance_metadata('vpc_subnet_different_az')

def vpc_subnet_different_az_check(ec2_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for vpc_subnet_different_az.
    
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
        
        # Group subnets by VPC
        vpc_subnets = {}
        for subnet in subnets:
            vpc_id = subnet.get('VpcId')
            if vpc_id not in vpc_subnets:
                vpc_subnets[vpc_id] = []
            vpc_subnets[vpc_id].append(subnet)
        
        # Check each VPC for subnet distribution across AZs
        for vpc_id, vpc_subnet_list in vpc_subnets.items():
            availability_zones = set()
            subnet_details = []
            
            for subnet in vpc_subnet_list:
                az = subnet.get('AvailabilityZone')
                availability_zones.add(az)
                subnet_details.append({
                    'subnet_id': subnet.get('SubnetId'),
                    'availability_zone': az,
                    'cidr_block': subnet.get('CidrBlock')
                })
            
            # Determine compliance - VPC should have subnets in multiple AZs
            num_azs = len(availability_zones)
            num_subnets = len(vpc_subnet_list)
            
            # Compliant if either:
            # 1. Only one subnet (can't be distributed)
            # 2. Multiple subnets distributed across multiple AZs
            is_compliant = num_subnets == 1 or num_azs > 1
            
            status = 'COMPLIANT' if is_compliant else 'NON_COMPLIANT'
            compliance_status = 'PASS' if is_compliant else 'FAIL'
            
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'VPC',
                'resource_id': vpc_id,
                'status': status,
                'compliance_status': compliance_status,
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                'recommendation': COMPLIANCE_DATA.get('recommendation', 'Distribute VPC subnets across multiple availability zones for high availability'),
                'details': {
                    'vpc_id': vpc_id,
                    'subnet_count': num_subnets,
                    'availability_zones_count': num_azs,
                    'availability_zones': list(availability_zones),
                    'subnets': subnet_details,
                    'is_distributed': is_compliant
                }
            }
            
            findings.append(finding)
        
        # If no subnets found, add informational finding
        if not subnets:
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'VPC',
                'resource_id': 'NO_VPCS',
                'status': 'COMPLIANT',
                'compliance_status': 'PASS',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                'recommendation': 'No VPCs or subnets found in this region',
                'details': {
                    'message': 'No VPCs or subnets found',
                    'vpcs_count': 0
                }
            }
            findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in vpc_subnet_different_az check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'VPC',
            'status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Distribute VPC subnets across multiple availability zones for high availability'),
            'error': str(e)
        })
        
    return findings

def vpc_subnet_different_az(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=vpc_subnet_different_az_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    args = setup_command_line_interface(COMPLIANCE_DATA)
    results = vpc_subnet_different_az(
        profile_name=args.profile,
        region_name=args.region
    )
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

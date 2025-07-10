#!/usr/bin/env python3
"""
iso27001_2022_aws - ec2_instance_port_telnet_exposed_to_internet

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
                    'recommendation': entry.get('Recommendation', 'Block telnet port (23) access from the internet by restricting security group rules')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'iso27001_2022_aws',
        'function_name': 'ec2_instance_port_telnet_exposed_to_internet',
        'id': 'ISO-27001-2022-A.12.6',
        'name': 'Network Security Controls',
        'description': 'Logs that record activities, exceptions, faults and other relevant events should be produced, stored, protected and analysed.',
        'api_function': 'client = boto3.client(\'ec2\')',
        'user_function': 'describe_security_groups()',
        'risk_level': 'HIGH',
        'recommendation': 'Block telnet port (23) access from the internet by restricting security group rules'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('ec2_instance_port_telnet_exposed_to_internet')

def check_telnet_port_exposure(security_group: Dict[str, Any]) -> bool:
    """
    Check if a security group allows telnet port (23) access from the internet.
    
    Args:
        security_group: Security group configuration
        
    Returns:
        bool: True if telnet is exposed to internet, False otherwise
    """
    telnet_port = 23
    
    for rule in security_group.get('IpPermissions', []):
        # Check if rule covers telnet port
        from_port = rule.get('FromPort', 0)
        to_port = rule.get('ToPort', 65535)
        
        if from_port <= telnet_port <= to_port:
            # Check if rule allows access from internet (0.0.0.0/0)
            for ip_range in rule.get('IpRanges', []):
                if ip_range.get('CidrIp') == '0.0.0.0/0':
                    return True
            
            # Check IPv6 ranges for ::/0
            for ipv6_range in rule.get('Ipv6Ranges', []):
                if ipv6_range.get('CidrIpv6') == '::/0':
                    return True
    
    return False

def ec2_instance_port_telnet_exposed_to_internet_check(ec2_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for ec2_instance_port_telnet_exposed_to_internet.
    
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
        # Get all security groups
        response = ec2_client.describe_security_groups()
        security_groups = response.get('SecurityGroups', [])
        
        if not security_groups:
            # No security groups found
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'EC2SecurityGroup',
                'resource_id': f'no-security-groups-{region}',
                'status': 'COMPLIANT',
                'compliance_status': 'PASS',
                'risk_level': 'LOW',
                'recommendation': 'No security groups found in this region',
                'details': {
                    'security_groups_count': 0,
                    'message': 'No security groups found to check for telnet exposure'
                }
            }
            findings.append(finding)
            return findings
        
        # Check each security group for telnet exposure
        telnet_exposed_count = 0
        for sg in security_groups:
            sg_id = sg.get('GroupId', 'unknown')
            sg_name = sg.get('GroupName', 'unknown')
            vpc_id = sg.get('VpcId', 'classic')
            
            is_telnet_exposed = check_telnet_port_exposure(sg)
            
            if is_telnet_exposed:
                telnet_exposed_count += 1
                status = 'NON_COMPLIANT'
                compliance_status = 'FAIL'
                risk_level = COMPLIANCE_DATA.get('risk_level', 'HIGH')
                recommendation = COMPLIANCE_DATA.get('recommendation', 'Block telnet port (23) access from the internet')
            else:
                status = 'COMPLIANT'
                compliance_status = 'PASS'
                risk_level = 'LOW'
                recommendation = 'Security group properly restricts telnet access from the internet'
            
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'EC2SecurityGroup',
                'resource_id': sg_id,
                'status': status,
                'compliance_status': compliance_status,
                'risk_level': risk_level,
                'recommendation': recommendation,
                'details': {
                    'security_group_id': sg_id,
                    'security_group_name': sg_name,
                    'vpc_id': vpc_id,
                    'telnet_exposed_to_internet': is_telnet_exposed,
                    'telnet_port': 23,
                    'description': sg.get('Description', ''),
                    'owner_id': sg.get('OwnerId', ''),
                    'ingress_rules_count': len(sg.get('IpPermissions', [])),
                    'security_note': 'Telnet transmits data in plain text and should not be accessible from the internet'
                }
            }
            
            findings.append(finding)
        
        logger.info(f"Checked {len(security_groups)} security groups, found {telnet_exposed_count} with telnet exposed to internet")
        
    except Exception as e:
        logger.error(f"Error in ec2_instance_port_telnet_exposed_to_internet check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'EC2SecurityGroup',
            'resource_id': f'error-check-{region}',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Block telnet port (23) access from the internet'),
            'error': str(e)
        })
        
    return findings

def ec2_instance_port_telnet_exposed_to_internet(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=ec2_instance_port_telnet_exposed_to_internet_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = ec2_instance_port_telnet_exposed_to_internet(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

#!/usr/bin/env python3
"""
aws_foundational_security_best_practices_aws - ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22

Security groups should not allow unrestricted access from the internet to port 22
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
                    'recommendation': entry.get('Recommendation', 'Restrict SSH access to specific IP ranges')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'aws_foundational_security_best_practices_aws',
        'function_name': 'ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22',
        'id': 'EC2.19',
        'name': 'Security groups should not allow unrestricted access from the internet to port 22',
        'description': 'This control checks whether security groups allow unrestricted access from the internet to port 22.',
        'api_function': 'client = boto3.client(\'ec2\')',
        'user_function': 'describe_security_groups()',
        'risk_level': 'HIGH',
        'recommendation': 'Restrict SSH access to specific IP ranges'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22')

def ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22_check(ec2_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22.
    
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
        
        for sg in security_groups:
            sg_id = sg['GroupId']
            sg_name = sg.get('GroupName', 'Unknown')
            vpc_id = sg.get('VpcId', 'Classic')
            
            # Check ingress rules for unrestricted SSH access
            ingress_rules = sg.get('IpPermissions', [])
            violations = []
            
            for rule in ingress_rules:
                from_port = rule.get('FromPort')
                to_port = rule.get('ToPort')
                protocol = rule.get('IpProtocol', '')
                
                # Check if rule allows port 22 (SSH)
                if (protocol == 'tcp' and 
                    ((from_port is not None and to_port is not None and from_port <= 22 <= to_port) or
                     (from_port == 22 and to_port == 22))):
                    
                    # Check if it allows access from anywhere (0.0.0.0/0)
                    ip_ranges = rule.get('IpRanges', [])
                    for ip_range in ip_ranges:
                        cidr = ip_range.get('CidrIp', '')
                        if cidr == '0.0.0.0/0':
                            violations.append({
                                'protocol': protocol,
                                'from_port': from_port,
                                'to_port': to_port,
                                'cidr': cidr,
                                'description': ip_range.get('Description', 'No description')
                            })
                    
                    # Check IPv6 ranges
                    ipv6_ranges = rule.get('Ipv6Ranges', [])
                    for ipv6_range in ipv6_ranges:
                        cidr_ipv6 = ipv6_range.get('CidrIpv6', '')
                        if cidr_ipv6 == '::/0':
                            violations.append({
                                'protocol': protocol,
                                'from_port': from_port,
                                'to_port': to_port,
                                'cidr': cidr_ipv6,
                                'description': ipv6_range.get('Description', 'No description')
                            })
            
            # Determine compliance status
            if violations:
                status = 'NON_COMPLIANT'
                compliance_status = 'FAIL'
            else:
                status = 'COMPLIANT'
                compliance_status = 'PASS'
            
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'EC2 Security Group',
                'resource_id': sg_id,
                'status': status,
                'compliance_status': compliance_status,
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                'recommendation': COMPLIANCE_DATA.get('recommendation', 'Restrict SSH access to specific IP ranges'),
                'details': {
                    'security_group_id': sg_id,
                    'security_group_name': sg_name,
                    'vpc_id': vpc_id,
                    'violations_count': len(violations),
                    'violations': violations,
                    'total_ingress_rules': len(ingress_rules),
                    'is_default_sg': sg_name == 'default'
                }
            }
            
            findings.append(finding)
            
    except Exception as e:
        logger.error(f"Error in ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22 check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'EC2 Security Group',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Restrict SSH access to specific IP ranges'),
            'error': str(e)
        })
        
    return findings

def ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

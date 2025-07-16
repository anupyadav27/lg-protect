#!/usr/bin/env python3
"""
iso27001_2022_aws - ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_telnet_23

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
    """Load compliance metadata from compliance_checks.json."""
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
                    'recommendation': entry.get('Recommendation', 'Restrict security group access to Telnet port 23 from the internet')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'iso27001_2022_aws',
        'function_name': 'ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_telnet_23',
        'id': 'EC2.SG.TELNET',
        'name': 'Security groups should not allow unrestricted access to Telnet port 23',
        'description': 'Security mechanisms, service levels and service requirements of network services should be identified, implemented and monitored.',
        'api_function': 'client = boto3.client(\'ec2\')',
        'user_function': 'describe_security_groups()',
        'risk_level': 'HIGH',
        'recommendation': 'Restrict security group access to Telnet port 23 from the internet'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_telnet_23')

def ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_telnet_23_check(ec2_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_telnet_23.
    
    Args:
        ec2_client: Boto3 EC2 client (auto-created by framework)
        region (str): AWS region (auto-managed by framework)
        profile (str): AWS profile name (auto-managed by framework)
        logger: Logger instance (auto-configured by framework)
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    telnet_port = 23
    
    try:
        # Get all security groups
        paginator = ec2_client.get_paginator('describe_security_groups')
        
        for page in paginator.paginate():
            security_groups = page.get('SecurityGroups', [])
            
            for sg in security_groups:
                group_id = sg['GroupId']
                group_name = sg.get('GroupName', 'Unknown')
                vpc_id = sg.get('VpcId', 'Classic')
                
                try:
                    # Check inbound rules for Telnet port exposure
                    telnet_exposed = False
                    exposed_rules = []
                    
                    for rule in sg.get('IpPermissions', []):
                        from_port = rule.get('FromPort')
                        to_port = rule.get('ToPort')
                        ip_protocol = rule.get('IpProtocol', '')
                        
                        # Check if rule covers Telnet port 23
                        if (ip_protocol == 'tcp' and 
                            ((from_port is None and to_port is None) or  # All ports
                             (from_port is not None and to_port is not None and from_port <= telnet_port <= to_port))):
                            
                            # Check for internet access (0.0.0.0/0)
                            for ip_range in rule.get('IpRanges', []):
                                if ip_range.get('CidrIp') == '0.0.0.0/0':
                                    telnet_exposed = True
                                    exposed_rules.append({
                                        'from_port': from_port,
                                        'to_port': to_port,
                                        'protocol': ip_protocol,
                                        'cidr': ip_range.get('CidrIp'),
                                        'description': ip_range.get('Description', 'No description')
                                    })
                            
                            # Check for IPv6 internet access (::/0)
                            for ipv6_range in rule.get('Ipv6Ranges', []):
                                if ipv6_range.get('CidrIpv6') == '::/0':
                                    telnet_exposed = True
                                    exposed_rules.append({
                                        'from_port': from_port,
                                        'to_port': to_port,
                                        'protocol': ip_protocol,
                                        'cidr': ipv6_range.get('CidrIpv6'),
                                        'description': ipv6_range.get('Description', 'No description')
                                    })
                    
                    if telnet_exposed:
                        findings.append({
                            'region': region,
                            'profile': profile,
                            'resource_type': 'Security Group',
                            'resource_id': group_id,
                            'status': 'NON_COMPLIANT',
                            'compliance_status': 'FAIL',
                            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Disable Telnet access and use SSH instead'),
                            'details': {
                                'group_id': group_id,
                                'group_name': group_name,
                                'vpc_id': vpc_id,
                                'exposed_port': telnet_port,
                                'exposed_rules': exposed_rules,
                                'issue': f'Security group allows unrestricted internet access to Telnet port {telnet_port} (insecure protocol)'
                            }
                        })
                    else:
                        findings.append({
                            'region': region,
                            'profile': profile,
                            'resource_type': 'Security Group',
                            'resource_id': group_id,
                            'status': 'COMPLIANT',
                            'compliance_status': 'PASS',
                            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Continue monitoring security group rules'),
                            'details': {
                                'group_id': group_id,
                                'group_name': group_name,
                                'vpc_id': vpc_id,
                                'exposed_port': telnet_port,
                                'internet_accessible': False
                            }
                        })
                        
                except Exception as sg_error:
                    logger.error(f"Error checking security group {group_id}: {sg_error}")
                    findings.append({
                        'region': region,
                        'profile': profile,
                        'resource_type': 'Security Group',
                        'resource_id': group_id,
                        'status': 'ERROR',
                        'compliance_status': 'ERROR',
                        'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                        'recommendation': COMPLIANCE_DATA.get('recommendation', 'Resolve errors and verify security group rules'),
                        'error': str(sg_error)
                    })
                    
    except Exception as e:
        logger.error(f"Error in ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_telnet_23 check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'Security Group',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Resolve errors and verify security group rules'),
            'error': str(e)
        })
        
    return findings

def ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_telnet_23(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_telnet_23_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_telnet_23(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

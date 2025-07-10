#!/usr/bin/env python3
"""
pci_3.2.1_aws - ec2_instance_port_oracle_exposed_to_internet

Ensure Oracle database ports (1521, 2483, 2484) are not exposed to the internet through security groups
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
                    'recommendation': entry.get('Recommendation', 'Restrict Oracle database port access to specific IP ranges')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    return {
        'compliance_name': 'pci_3.2.1_aws',
        'function_name': 'ec2_instance_port_oracle_exposed_to_internet',
        'id': 'PCI-3.2.1-EC2-Oracle',
        'name': 'Oracle Database Port Internet Exposure',
        'description': 'Ensure Oracle database ports are not exposed to the internet',
        'api_function': 'ec2 = boto3.client(\'ec2\')',
        'user_function': 'describe_security_groups()',
        'risk_level': 'HIGH',
        'recommendation': 'Restrict Oracle database port access to specific IP ranges'
    }

COMPLIANCE_DATA = load_compliance_metadata('ec2_instance_port_oracle_exposed_to_internet')

# Oracle database ports that should not be exposed to the internet
ORACLE_PORTS = [
    {'port': 1521, 'description': 'Oracle Database Listener (default)'},
    {'port': 2483, 'description': 'Oracle Database SSL/TLS'},
    {'port': 2484, 'description': 'Oracle Database SSL/TLS (alternative)'},
    {'port': 1522, 'description': 'Oracle Database Listener (alternative)'},
    {'port': 1526, 'description': 'Oracle Database TNS Listener'},
    {'port': 1575, 'description': 'Oracle Names Server'},
    {'port': 1630, 'description': 'Oracle Connection Manager'},
    {'port': 1830, 'description': 'Oracle Net8 Cman'},
]

def analyze_oracle_port_exposure(security_group: Dict[str, Any]) -> Dict[str, Any]:
    """Analyze security group rules for Oracle port exposure to the internet."""
    exposed_oracle_ports = []
    total_oracle_rules = 0
    
    group_id = security_group.get('GroupId', 'unknown')
    group_name = security_group.get('GroupName', 'unknown')
    
    # Check inbound rules
    for rule in security_group.get('IpPermissions', []):
        from_port = rule.get('FromPort')
        to_port = rule.get('ToPort')
        ip_protocol = rule.get('IpProtocol', '')
        
        # Check if rule covers any Oracle ports
        for oracle_port_info in ORACLE_PORTS:
            oracle_port = oracle_port_info['port']
            
            # Check if this rule affects the Oracle port
            port_in_range = False
            if from_port is not None and to_port is not None:
                port_in_range = from_port <= oracle_port <= to_port
            elif from_port is not None:
                port_in_range = from_port == oracle_port
            elif ip_protocol == '-1':  # All protocols/ports
                port_in_range = True
            
            if port_in_range:
                total_oracle_rules += 1
                
                # Check if exposed to internet (0.0.0.0/0 or ::/0)
                for ip_range in rule.get('IpRanges', []):
                    cidr = ip_range.get('CidrIp', '')
                    if cidr in ['0.0.0.0/0']:
                        exposed_oracle_ports.append({
                            'port': oracle_port,
                            'description': oracle_port_info['description'],
                            'protocol': ip_protocol if ip_protocol != '-1' else 'all',
                            'from_port': from_port,
                            'to_port': to_port,
                            'cidr': cidr,
                            'rule_description': ip_range.get('Description', ''),
                            'exposure_type': 'IPv4_internet'
                        })
                
                # Check IPv6 ranges
                for ipv6_range in rule.get('Ipv6Ranges', []):
                    cidr_ipv6 = ipv6_range.get('CidrIpv6', '')
                    if cidr_ipv6 in ['::/0']:
                        exposed_oracle_ports.append({
                            'port': oracle_port,
                            'description': oracle_port_info['description'],
                            'protocol': ip_protocol if ip_protocol != '-1' else 'all',
                            'from_port': from_port,
                            'to_port': to_port,
                            'cidr': cidr_ipv6,
                            'rule_description': ipv6_range.get('Description', ''),
                            'exposure_type': 'IPv6_internet'
                        })
    
    return {
        'group_id': group_id,
        'group_name': group_name,
        'exposed_oracle_ports': exposed_oracle_ports,
        'total_oracle_rules': total_oracle_rules,
        'has_oracle_exposure': len(exposed_oracle_ports) > 0,
        'exposed_ports_count': len(exposed_oracle_ports)
    }

def ec2_instance_port_oracle_exposed_to_internet_check(ec2_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """Perform the actual compliance check for ec2_instance_port_oracle_exposed_to_internet."""
    findings = []
    
    try:
        # Get all security groups
        response = ec2_client.describe_security_groups()
        security_groups = response.get('SecurityGroups', [])
        
        if not security_groups:
            finding = {
                'region': region, 'profile': profile, 'resource_type': 'SecurityGroup',
                'resource_id': f'no-security-groups-{region}', 'status': 'COMPLIANT',
                'compliance_status': 'PASS', 'risk_level': 'LOW',
                'recommendation': 'No security groups found in this region',
                'details': {'security_groups_count': 0, 'message': 'No security groups found to check for Oracle port exposure'}
            }
            findings.append(finding)
            return findings
        
        # Check each security group
        exposed_groups = 0
        total_groups_checked = 0
        
        for sg in security_groups:
            total_groups_checked += 1
            group_id = sg.get('GroupId', 'unknown')
            
            # Analyze Oracle port exposure
            exposure_analysis = analyze_oracle_port_exposure(sg)
            
            if exposure_analysis['has_oracle_exposure']:
                exposed_groups += 1
                status = 'NON_COMPLIANT'
                compliance_status = 'FAIL'
                risk_level = COMPLIANCE_DATA.get('risk_level', 'HIGH')
                recommendation = COMPLIANCE_DATA.get('recommendation', 'Restrict Oracle database port access')
            else:
                status = 'COMPLIANT'
                compliance_status = 'PASS'
                risk_level = 'LOW'
                recommendation = 'No Oracle database ports exposed to the internet'
            
            # Get associated instances if any
            instances_response = ec2_client.describe_instances(
                Filters=[{'Name': 'instance.group-id', 'Values': [group_id]}]
            )
            
            associated_instances = []
            for reservation in instances_response.get('Reservations', []):
                for instance in reservation.get('Instances', []):
                    if instance.get('State', {}).get('Name') not in ['terminated', 'shutting-down']:
                        associated_instances.append({
                            'instance_id': instance.get('InstanceId', 'unknown'),
                            'instance_type': instance.get('InstanceType', 'unknown'),
                            'state': instance.get('State', {}).get('Name', 'unknown')
                        })
            
            finding = {
                'region': region, 'profile': profile, 'resource_type': 'SecurityGroup',
                'resource_id': group_id, 'status': status, 'compliance_status': compliance_status,
                'risk_level': risk_level, 'recommendation': recommendation,
                'details': {
                    'group_id': group_id,
                    'group_name': exposure_analysis['group_name'],
                    'vpc_id': sg.get('VpcId', 'unknown'),
                    'description': sg.get('Description', ''),
                    'exposed_oracle_ports': exposure_analysis['exposed_oracle_ports'],
                    'exposed_ports_count': exposure_analysis['exposed_ports_count'],
                    'total_oracle_rules': exposure_analysis['total_oracle_rules'],
                    'has_oracle_exposure': exposure_analysis['has_oracle_exposure'],
                    'associated_instances': associated_instances,
                    'associated_instances_count': len(associated_instances),
                    'security_implications': 'Oracle database exposure can lead to unauthorized data access',
                    'common_oracle_ports': [f"{p['port']} ({p['description']})" for p in ORACLE_PORTS[:4]],
                    'remediation_steps': [
                        'Remove 0.0.0.0/0 CIDR from Oracle port rules',
                        'Use specific IP ranges or security group references',
                        'Consider using VPN or bastion hosts for database access',
                        'Implement database-level access controls'
                    ]
                }
            }
            findings.append(finding)
        
        logger.info(f"Checked {total_groups_checked} security groups, found {exposed_groups} with Oracle port exposure")
        
    except Exception as e:
        logger.error(f"Error in ec2_instance_port_oracle_exposed_to_internet check for {region}: {e}")
        findings.append({
            'region': region, 'profile': profile, 'resource_type': 'SecurityGroup',
            'resource_id': f'error-check-{region}', 'status': 'ERROR', 'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Restrict Oracle database port access'),
            'error': str(e)
        })
        
    return findings

def ec2_instance_port_oracle_exposed_to_internet(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=ec2_instance_port_oracle_exposed_to_internet_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    args = setup_command_line_interface(COMPLIANCE_DATA)
    results = ec2_instance_port_oracle_exposed_to_internet(
        profile_name=args.profile, region_name=args.region
    )
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

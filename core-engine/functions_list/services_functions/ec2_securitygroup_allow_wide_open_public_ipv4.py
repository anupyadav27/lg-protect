#!/usr/bin/env python3
"""
iso27001_2022_aws - ec2_securitygroup_allow_wide_open_public_ipv4

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
                    'risk_level': entry.get('Risk Level', 'MEDIUM'),
                    'recommendation': entry.get('Recommendation', 'Review and remediate as needed')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'iso27001_2022_aws',
        'function_name': 'ec2_securitygroup_allow_wide_open_public_ipv4',
        'id': 'A.13.1.3',
        'name': 'Security groups should not allow unrestricted access from 0.0.0.0/0',
        'description': 'Security mechanisms, service levels and service requirements of network services should be identified, implemented and monitored',
        'api_function': 'client = boto3.client("ec2")',
        'user_function': 'describe_security_groups()',
        'risk_level': 'HIGH',
        'recommendation': 'Restrict security group rules to specific IP ranges instead of 0.0.0.0/0'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('ec2_securitygroup_allow_wide_open_public_ipv4')

def ec2_securitygroup_allow_wide_open_public_ipv4_check(ec2_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for ec2_securitygroup_allow_wide_open_public_ipv4.
    
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
        logger.info(f"Checking security groups for wide-open public IPv4 access in region {region}")
        
        # Get all security groups
        security_groups_response = ec2_client.describe_security_groups()
        security_groups = security_groups_response.get('SecurityGroups', [])
        
        if not security_groups:
            logger.info(f"No security groups found in region {region}")
            return findings
        
        # Check each security group for wide-open rules
        for sg in security_groups:
            group_id = sg.get('GroupId', 'unknown')
            group_name = sg.get('GroupName', 'unknown')
            vpc_id = sg.get('VpcId', 'unknown')
            description = sg.get('Description', '')
            
            # Check inbound rules (IpPermissions)
            ip_permissions = sg.get('IpPermissions', [])
            wide_open_rules = []
            
            for rule in ip_permissions:
                from_port = rule.get('FromPort', 'All')
                to_port = rule.get('ToPort', 'All')
                ip_protocol = rule.get('IpProtocol', 'unknown')
                
                # Check IPv4 ranges
                for ip_range in rule.get('IpRanges', []):
                    cidr_ip = ip_range.get('CidrIp', '')
                    description = ip_range.get('Description', '')
                    
                    # Check for wide-open access (0.0.0.0/0)
                    if cidr_ip == '0.0.0.0/0':
                        wide_open_rules.append({
                            'type': 'IPv4',
                            'cidr': cidr_ip,
                            'from_port': from_port,
                            'to_port': to_port,
                            'protocol': ip_protocol,
                            'description': description
                        })
                
                # Check IPv6 ranges for completeness
                for ipv6_range in rule.get('Ipv6Ranges', []):
                    cidr_ipv6 = ipv6_range.get('CidrIpv6', '')
                    description = ipv6_range.get('Description', '')
                    
                    # Check for wide-open IPv6 access (::/0)
                    if cidr_ipv6 == '::/0':
                        wide_open_rules.append({
                            'type': 'IPv6',
                            'cidr': cidr_ipv6,
                            'from_port': from_port,
                            'to_port': to_port,
                            'protocol': ip_protocol,
                            'description': description
                        })
            
            # Determine compliance status
            if wide_open_rules:
                # Non-compliant: Security group has wide-open rules
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'EC2 Security Group',
                    'resource_id': group_id,
                    'status': 'NON_COMPLIANT',
                    'compliance_status': 'FAIL',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Restrict security group access'),
                    'details': {
                        'group_id': group_id,
                        'group_name': group_name,
                        'vpc_id': vpc_id,
                        'description': description,
                        'issue': 'Security group allows unrestricted access from 0.0.0.0/0 or ::/0',
                        'wide_open_rules_count': len(wide_open_rules),
                        'wide_open_rules': wide_open_rules,
                        'security_risk': 'Unrestricted access increases attack surface and potential for unauthorized access',
                        'remediation_steps': [
                            'Review each wide-open rule for necessity',
                            'Replace 0.0.0.0/0 with specific IP ranges or security groups',
                            'Use principle of least privilege',
                            'Consider using AWS Systems Manager Session Manager for administrative access',
                            'Implement network ACLs for additional layer of security'
                        ],
                        'total_inbound_rules': len(ip_permissions),
                        'tags': sg.get('Tags', [])
                    }
                }
            else:
                # Compliant: Security group does not have wide-open rules
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'EC2 Security Group',
                    'resource_id': group_id,
                    'status': 'COMPLIANT',
                    'compliance_status': 'PASS',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Security group properly configured'),
                    'details': {
                        'group_id': group_id,
                        'group_name': group_name,
                        'vpc_id': vpc_id,
                        'description': description,
                        'total_inbound_rules': len(ip_permissions),
                        'tags': sg.get('Tags', [])
                    }
                }
            
            findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in ec2_securitygroup_allow_wide_open_public_ipv4 check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'EC2 Security Group',
            'status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Review and remediate as needed'),
            'error': str(e)
        })
        
    return findings

def ec2_securitygroup_allow_wide_open_public_ipv4(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=ec2_securitygroup_allow_wide_open_public_ipv4_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = ec2_securitygroup_allow_wide_open_public_ipv4(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

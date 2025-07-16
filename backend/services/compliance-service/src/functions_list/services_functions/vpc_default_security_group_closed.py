#!/usr/bin/env python3
"""
iso27001_2022_aws - vpc_default_security_group_closed

Firewalls and router configurations should be reviewed at least every six months to confirm that they provide an appropriate configuration.
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
        'function_name': 'vpc_default_security_group_closed',
        'id': 'VPC-001',
        'name': 'VPC Default Security Group Closed',
        'description': 'Firewalls and router configurations should be reviewed at least every six months to confirm that they provide an appropriate configuration.',
        'api_function': 'client=boto3.client("ec2")',
        'user_function': 'describe_security_groups()',
        'risk_level': 'HIGH',
        'recommendation': 'Remove all rules from default security groups to prevent unintended access'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('vpc_default_security_group_closed')

def vpc_default_security_group_closed_check(ec2_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for vpc_default_security_group_closed.
    
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
        # Get all security groups that are default groups
        response = ec2_client.describe_security_groups(
            Filters=[
                {'Name': 'group-name', 'Values': ['default']}
            ]
        )
        security_groups = response.get('SecurityGroups', [])
        
        if not security_groups:
            logger.info(f"No default security groups found in region {region}")
            return findings
        
        for sg in security_groups:
            sg_id = sg.get('GroupId', 'Unknown')
            sg_name = sg.get('GroupName', 'Unknown')
            vpc_id = sg.get('VpcId', 'Unknown')
            
            # Get inbound and outbound rules
            ip_permissions = sg.get('IpPermissions', [])
            ip_permissions_egress = sg.get('IpPermissionsEgress', [])
            
            # Check if the default security group has any rules
            has_inbound_rules = len(ip_permissions) > 0
            has_outbound_rules = len(ip_permissions_egress) > 0
            
            # Filter out the default allow-all egress rule that AWS adds
            # Default egress rule: protocol=-1, port=all, destination=0.0.0.0/0
            non_default_egress_rules = []
            for rule in ip_permissions_egress:
                # Check if this is the default "allow all outbound" rule
                is_default_rule = (
                    rule.get('IpProtocol') == '-1' and
                    len(rule.get('IpRanges', [])) == 1 and
                    rule['IpRanges'][0].get('CidrIp') == '0.0.0.0/0' and
                    not rule.get('UserIdGroupPairs', []) and
                    not rule.get('Ipv6Ranges', []) and
                    not rule.get('PrefixListIds', [])
                )
                
                if not is_default_rule:
                    non_default_egress_rules.append(rule)
            
            has_custom_outbound_rules = len(non_default_egress_rules) > 0
            
            # Default security group should have no inbound rules and only the default outbound rule
            is_compliant = not has_inbound_rules and not has_custom_outbound_rules
            
            if is_compliant:
                # Default security group is properly closed - COMPLIANT
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'Default_Security_Group',
                    'resource_id': f"{sg_id} ({vpc_id})",
                    'status': 'COMPLIANT',
                    'compliance_status': 'PASS',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Maintain closed configuration'),
                    'details': {
                        'security_group_id': sg_id,
                        'security_group_name': sg_name,
                        'vpc_id': vpc_id,
                        'inbound_rules_count': 0,
                        'outbound_rules_count': len(ip_permissions_egress),
                        'custom_outbound_rules_count': len(non_default_egress_rules),
                        'is_properly_closed': True
                    }
                }
            else:
                # Default security group has rules - NON_COMPLIANT
                issues = []
                if has_inbound_rules:
                    issues.append(f'{len(ip_permissions)} inbound rule(s) configured')
                if has_custom_outbound_rules:
                    issues.append(f'{len(non_default_egress_rules)} custom outbound rule(s) configured')
                
                # Get details of problematic rules
                problematic_rules = []
                
                # Add inbound rules details
                for rule in ip_permissions:
                    rule_detail = {
                        'type': 'inbound',
                        'protocol': rule.get('IpProtocol', 'Unknown'),
                        'from_port': rule.get('FromPort', 'N/A'),
                        'to_port': rule.get('ToPort', 'N/A'),
                        'sources': []
                    }
                    
                    # Add IP ranges
                    for ip_range in rule.get('IpRanges', []):
                        rule_detail['sources'].append(ip_range.get('CidrIp', 'Unknown'))
                    
                    # Add security group references
                    for sg_ref in rule.get('UserIdGroupPairs', []):
                        rule_detail['sources'].append(f"sg-{sg_ref.get('GroupId', 'Unknown')}")
                    
                    problematic_rules.append(rule_detail)
                
                # Add custom outbound rules details
                for rule in non_default_egress_rules:
                    rule_detail = {
                        'type': 'outbound',
                        'protocol': rule.get('IpProtocol', 'Unknown'),
                        'from_port': rule.get('FromPort', 'N/A'),
                        'to_port': rule.get('ToPort', 'N/A'),
                        'destinations': []
                    }
                    
                    # Add IP ranges
                    for ip_range in rule.get('IpRanges', []):
                        rule_detail['destinations'].append(ip_range.get('CidrIp', 'Unknown'))
                    
                    # Add security group references
                    for sg_ref in rule.get('UserIdGroupPairs', []):
                        rule_detail['destinations'].append(f"sg-{sg_ref.get('GroupId', 'Unknown')}")
                    
                    problematic_rules.append(rule_detail)
                
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'Default_Security_Group',
                    'resource_id': f"{sg_id} ({vpc_id})",
                    'status': 'NON_COMPLIANT',
                    'compliance_status': 'FAIL',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                    'recommendation': 'Remove all rules from this default security group',
                    'details': {
                        'security_group_id': sg_id,
                        'security_group_name': sg_name,
                        'vpc_id': vpc_id,
                        'inbound_rules_count': len(ip_permissions),
                        'outbound_rules_count': len(ip_permissions_egress),
                        'custom_outbound_rules_count': len(non_default_egress_rules),
                        'is_properly_closed': False,
                        'issues': issues,
                        'problematic_rules': problematic_rules
                    }
                }
            
            findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in vpc_default_security_group_closed check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'Default_Security_Group',
            'status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Review default security group configuration'),
            'error': str(e)
        })
        
    return findings

def vpc_default_security_group_closed(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=vpc_default_security_group_closed_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = vpc_default_security_group_closed(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

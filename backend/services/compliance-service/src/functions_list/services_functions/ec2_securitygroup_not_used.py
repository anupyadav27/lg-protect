#!/usr/bin/env python3
"""
iso27001_2022_aws - ec2_securitygroup_not_used

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
                    'risk_level': entry.get('Risk Level', 'LOW'),
                    'recommendation': entry.get('Recommendation', 'Remove unused security groups to reduce attack surface')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'iso27001_2022_aws',
        'function_name': 'ec2_securitygroup_not_used',
        'id': 'EC2.SG.UNUSED',
        'name': 'Unused security groups should be removed',
        'description': 'Security mechanisms, service levels and service requirements of network services should be identified, implemented and monitored.',
        'api_function': 'client = boto3.client(\'ec2\')',
        'user_function': 'describe_security_groups(), describe_network_interfaces()',
        'risk_level': 'LOW',
        'recommendation': 'Remove unused security groups to reduce attack surface'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('ec2_securitygroup_not_used')

def ec2_securitygroup_not_used_check(ec2_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for ec2_securitygroup_not_used.
    
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
        security_groups_response = ec2_client.describe_security_groups()
        security_groups = security_groups_response.get('SecurityGroups', [])
        
        # Get all network interfaces to check which security groups are in use
        network_interfaces_response = ec2_client.describe_network_interfaces()
        network_interfaces = network_interfaces_response.get('NetworkInterfaces', [])
        
        # Collect security groups that are in use
        used_security_groups = set()
        for ni in network_interfaces:
            for sg in ni.get('Groups', []):
                used_security_groups.add(sg['GroupId'])
        
        # Check each security group
        for sg in security_groups:
            group_id = sg['GroupId']
            group_name = sg.get('GroupName', 'Unknown')
            vpc_id = sg.get('VpcId', 'Classic')
            
            try:
                # Skip default security groups as they cannot be deleted
                if group_name == 'default':
                    findings.append({
                        'region': region,
                        'profile': profile,
                        'resource_type': 'Security Group',
                        'resource_id': group_id,
                        'status': 'COMPLIANT',
                        'compliance_status': 'PASS',
                        'risk_level': COMPLIANCE_DATA.get('risk_level', 'LOW'),
                        'recommendation': COMPLIANCE_DATA.get('recommendation', 'Default security group cannot be deleted'),
                        'details': {
                            'group_id': group_id,
                            'group_name': group_name,
                            'vpc_id': vpc_id,
                            'is_default': True,
                            'reason': 'Default security group - cannot be deleted'
                        }
                    })
                    continue
                
                # Check if security group is being used
                if group_id not in used_security_groups:
                    # Check if it's referenced by other security groups
                    referenced_by_others = False
                    referencing_groups = []
                    
                    for other_sg in security_groups:
                        if other_sg['GroupId'] == group_id:
                            continue
                        
                        # Check inbound rules
                        for rule in other_sg.get('IpPermissions', []):
                            for user_id_group_pair in rule.get('UserIdGroupPairs', []):
                                if user_id_group_pair.get('GroupId') == group_id:
                                    referenced_by_others = True
                                    referencing_groups.append(other_sg['GroupId'])
                        
                        # Check outbound rules
                        for rule in other_sg.get('IpPermissionsEgress', []):
                            for user_id_group_pair in rule.get('UserIdGroupPairs', []):
                                if user_id_group_pair.get('GroupId') == group_id:
                                    referenced_by_others = True
                                    referencing_groups.append(other_sg['GroupId'])
                    
                    if not referenced_by_others:
                        findings.append({
                            'region': region,
                            'profile': profile,
                            'resource_type': 'Security Group',
                            'resource_id': group_id,
                            'status': 'NON_COMPLIANT',
                            'compliance_status': 'FAIL',
                            'risk_level': COMPLIANCE_DATA.get('risk_level', 'LOW'),
                            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Remove this unused security group'),
                            'details': {
                                'group_id': group_id,
                                'group_name': group_name,
                                'vpc_id': vpc_id,
                                'is_default': False,
                                'attached_to_resources': False,
                                'referenced_by_other_groups': False,
                                'issue': 'Security group is not used by any resources or referenced by other security groups'
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
                            'risk_level': COMPLIANCE_DATA.get('risk_level', 'LOW'),
                            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Security group is referenced by other groups'),
                            'details': {
                                'group_id': group_id,
                                'group_name': group_name,
                                'vpc_id': vpc_id,
                                'is_default': False,
                                'attached_to_resources': False,
                                'referenced_by_other_groups': True,
                                'referencing_groups': list(set(referencing_groups))
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
                        'risk_level': COMPLIANCE_DATA.get('risk_level', 'LOW'),
                        'recommendation': COMPLIANCE_DATA.get('recommendation', 'Security group is in use'),
                        'details': {
                            'group_id': group_id,
                            'group_name': group_name,
                            'vpc_id': vpc_id,
                            'is_default': False,
                            'attached_to_resources': True
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
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'LOW'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Resolve errors and verify security group usage'),
                    'error': str(sg_error)
                })
                
    except Exception as e:
        logger.error(f"Error in ec2_securitygroup_not_used check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'Security Group',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'LOW'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Resolve errors and verify security group usage'),
            'error': str(e)
        })
        
    return findings

def ec2_securitygroup_not_used(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=ec2_securitygroup_not_used_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = ec2_securitygroup_not_used(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

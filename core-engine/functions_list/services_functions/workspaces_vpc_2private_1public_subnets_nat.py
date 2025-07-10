#!/usr/bin/env python3
"""
iso27001_2022_aws - workspaces_vpc_2private_1public_subnets_nat

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
        'function_name': 'workspaces_vpc_2private_1public_subnets_nat',
        'id': 'WS-002',
        'name': 'WorkSpaces VPC Network Configuration',
        'description': 'Security mechanisms, service levels and service requirements of network services should be identified, implemented and monitored.',
        'api_function': 'client=boto3.client("ec2")',
        'user_function': 'describe_vpcs(), describe_subnets(), describe_route_tables(), describe_nat_gateways()',
        'risk_level': 'HIGH',
        'recommendation': 'Ensure WorkSpaces VPCs have proper network segmentation with 2 private and 1 public subnet with NAT gateway'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('workspaces_vpc_2private_1public_subnets_nat')

def workspaces_vpc_2private_1public_subnets_nat_check(ec2_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for workspaces_vpc_2private_1public_subnets_nat.
    
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
        # First get WorkSpaces to identify which VPCs are used by WorkSpaces
        try:
            workspaces_client = ec2_client.meta.client._client_config.session.client('workspaces', region_name=region)
            workspaces_response = workspaces_client.describe_workspace_directories()
            workspace_directories = workspaces_response.get('Directories', [])
            
            workspace_vpc_ids = set()
            for directory in workspace_directories:
                vpc_id = directory.get('VpcId')
                if vpc_id:
                    workspace_vpc_ids.add(vpc_id)
                    
        except Exception as ws_error:
            logger.warning(f"Could not retrieve WorkSpaces directories: {ws_error}")
            workspace_vpc_ids = set()
        
        # Get all VPCs
        vpc_response = ec2_client.describe_vpcs()
        vpcs = vpc_response.get('Vpcs', [])
        
        for vpc in vpcs:
            vpc_id = vpc.get('VpcId', 'Unknown')
            vpc_state = vpc.get('State', 'Unknown')
            
            # Only check VPCs that are used by WorkSpaces or if we couldn't determine WorkSpaces VPCs
            if not workspace_vpc_ids or vpc_id in workspace_vpc_ids:
                
                try:
                    # Get subnets for this VPC
                    subnets_response = ec2_client.describe_subnets(
                        Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}]
                    )
                    subnets = subnets_response.get('Subnets', [])
                    
                    # Get route tables for this VPC
                    route_tables_response = ec2_client.describe_route_tables(
                        Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}]
                    )
                    route_tables = route_tables_response.get('RouteTables', [])
                    
                    # Get NAT gateways for this VPC
                    nat_gateways_response = ec2_client.describe_nat_gateways(
                        Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}]
                    )
                    nat_gateways = nat_gateways_response.get('NatGateways', [])
                    
                    # Analyze subnet configuration
                    public_subnets = []
                    private_subnets = []
                    
                    for subnet in subnets:
                        subnet_id = subnet.get('SubnetId', 'Unknown')
                        is_public = subnet.get('MapPublicIpOnLaunch', False)
                        
                        # Check if subnet has route to internet gateway (more accurate check for public)
                        has_igw_route = False
                        for rt in route_tables:
                            # Check if this route table is associated with this subnet
                            associations = rt.get('Associations', [])
                            is_associated = any(
                                assoc.get('SubnetId') == subnet_id for assoc in associations
                            ) or any(
                                assoc.get('Main', False) for assoc in associations
                            )
                            
                            if is_associated:
                                routes = rt.get('Routes', [])
                                for route in routes:
                                    if (route.get('DestinationCidrBlock') == '0.0.0.0/0' and 
                                        route.get('GatewayId', '').startswith('igw-')):
                                        has_igw_route = True
                                        break
                        
                        if has_igw_route or is_public:
                            public_subnets.append(subnet_id)
                        else:
                            private_subnets.append(subnet_id)
                    
                    # Count active NAT gateways
                    active_nat_gateways = [
                        nat for nat in nat_gateways 
                        if nat.get('State') == 'available'
                    ]
                    
                    # Check compliance: 2 private subnets, 1 public subnet, and NAT gateway
                    has_correct_subnets = len(private_subnets) >= 2 and len(public_subnets) >= 1
                    has_nat_gateway = len(active_nat_gateways) >= 1
                    
                    is_compliant = has_correct_subnets and has_nat_gateway
                    
                    if is_compliant:
                        # Compliant configuration
                        finding = {
                            'region': region,
                            'profile': profile,
                            'resource_type': 'VPC',
                            'resource_id': vpc_id,
                            'status': 'COMPLIANT',
                            'compliance_status': 'PASS',
                            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Maintain network configuration'),
                            'details': {
                                'vpc_id': vpc_id,
                                'vpc_state': vpc_state,
                                'public_subnets_count': len(public_subnets),
                                'private_subnets_count': len(private_subnets),
                                'nat_gateways_count': len(active_nat_gateways),
                                'public_subnets': public_subnets,
                                'private_subnets': private_subnets,
                                'nat_gateway_ids': [nat.get('NatGatewayId') for nat in active_nat_gateways],
                                'used_by_workspaces': vpc_id in workspace_vpc_ids
                            }
                        }
                    else:
                        # Non-compliant configuration
                        issues = []
                        if len(private_subnets) < 2:
                            issues.append(f'Insufficient private subnets ({len(private_subnets)}/2)')
                        if len(public_subnets) < 1:
                            issues.append(f'No public subnets found')
                        if len(active_nat_gateways) < 1:
                            issues.append('No active NAT gateway found')
                        
                        finding = {
                            'region': region,
                            'profile': profile,
                            'resource_type': 'VPC',
                            'resource_id': vpc_id,
                            'status': 'NON_COMPLIANT',
                            'compliance_status': 'FAIL',
                            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                            'recommendation': 'Configure VPC with 2 private subnets, 1 public subnet, and NAT gateway',
                            'details': {
                                'vpc_id': vpc_id,
                                'vpc_state': vpc_state,
                                'public_subnets_count': len(public_subnets),
                                'private_subnets_count': len(private_subnets),
                                'nat_gateways_count': len(active_nat_gateways),
                                'public_subnets': public_subnets,
                                'private_subnets': private_subnets,
                                'nat_gateway_ids': [nat.get('NatGatewayId') for nat in active_nat_gateways],
                                'used_by_workspaces': vpc_id in workspace_vpc_ids,
                                'issues': issues
                            }
                        }
                    
                    findings.append(finding)
                    
                except Exception as vpc_error:
                    logger.error(f"Error analyzing VPC {vpc_id}: {vpc_error}")
                    finding = {
                        'region': region,
                        'profile': profile,
                        'resource_type': 'VPC',
                        'resource_id': vpc_id,
                        'status': 'ERROR',
                        'compliance_status': 'ERROR',
                        'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                        'recommendation': 'Review VPC network configuration',
                        'error': str(vpc_error),
                        'details': {
                            'vpc_id': vpc_id,
                            'vpc_state': vpc_state
                        }
                    }
                    findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in workspaces_vpc_2private_1public_subnets_nat check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'VPC',
            'status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Review VPC configuration'),
            'error': str(e)
        })
        
    return findings

def workspaces_vpc_2private_1public_subnets_nat(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=workspaces_vpc_2private_1public_subnets_nat_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = workspaces_vpc_2private_1public_subnets_nat(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

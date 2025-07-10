#!/usr/bin/env python3
"""
iso27001_2022_aws - vpc_subnet_separate_private_public

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
        'function_name': 'vpc_subnet_separate_private_public',
        'id': 'VPC-SUB-001',
        'name': 'VPC Subnet Separation',
        'description': 'Security mechanisms, service levels and service requirements of network services should be identified, implemented and monitored.',
        'api_function': 'client=boto3.client("ec2")',
        'user_function': 'describe_subnets(), describe_route_tables()',
        'risk_level': 'HIGH',
        'recommendation': 'Implement proper separation between private and public subnets'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('vpc_subnet_separate_private_public')

def vpc_subnet_separate_private_public_check(ec2_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for vpc_subnet_separate_private_public.
    
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
        # Get all subnets
        subnets_response = ec2_client.describe_subnets()
        subnets = subnets_response.get('Subnets', [])
        
        if not subnets:
            logger.info(f"No subnets found in region {region}")
            return findings
        
        # Get all route tables
        route_tables_response = ec2_client.describe_route_tables()
        route_tables = route_tables_response.get('RouteTables', [])
        
        # Get internet gateways to identify public routes
        igw_response = ec2_client.describe_internet_gateways()
        internet_gateways = igw_response.get('InternetGateways', [])
        igw_ids = [igw['InternetGatewayId'] for igw in internet_gateways]
        
        # Group subnets by VPC
        vpc_subnets = {}
        for subnet in subnets:
            vpc_id = subnet.get('VpcId')
            if vpc_id not in vpc_subnets:
                vpc_subnets[vpc_id] = []
            vpc_subnets[vpc_id].append(subnet)
        
        # Analyze each VPC
        for vpc_id, vpc_subnet_list in vpc_subnets.items():
            public_subnets = []
            private_subnets = []
            
            for subnet in vpc_subnet_list:
                subnet_id = subnet.get('SubnetId')
                availability_zone = subnet.get('AvailabilityZone')
                cidr_block = subnet.get('CidrBlock')
                map_public_ip = subnet.get('MapPublicIpOnLaunch', False)
                
                # Find associated route table
                associated_route_table = None
                is_public = False
                
                # Check explicit subnet associations first
                for rt in route_tables:
                    if rt.get('VpcId') == vpc_id:
                        for association in rt.get('Associations', []):
                            if association.get('SubnetId') == subnet_id:
                                associated_route_table = rt
                                break
                    if associated_route_table:
                        break
                
                # If no explicit association, use main route table
                if not associated_route_table:
                    for rt in route_tables:
                        if rt.get('VpcId') == vpc_id:
                            for association in rt.get('Associations', []):
                                if association.get('Main', False):
                                    associated_route_table = rt
                                    break
                        if associated_route_table:
                            break
                
                # Check if subnet has route to internet gateway (making it public)
                if associated_route_table:
                    for route in associated_route_table.get('Routes', []):
                        gateway_id = route.get('GatewayId', '')
                        destination = route.get('DestinationCidrBlock', '')
                        
                        # Check for default route (0.0.0.0/0) to internet gateway
                        if destination == '0.0.0.0/0' and gateway_id in igw_ids:
                            is_public = True
                            break
                
                subnet_info = {
                    'subnet_id': subnet_id,
                    'availability_zone': availability_zone,
                    'cidr_block': cidr_block,
                    'map_public_ip_on_launch': map_public_ip,
                    'is_public': is_public,
                    'route_table_id': associated_route_table.get('RouteTableId') if associated_route_table else 'None'
                }
                
                if is_public:
                    public_subnets.append(subnet_info)
                else:
                    private_subnets.append(subnet_info)
            
            # Analyze VPC subnet separation
            total_subnets = len(vpc_subnet_list)
            public_count = len(public_subnets)
            private_count = len(private_subnets)
            
            # Compliance criteria:
            # 1. VPC should have both public and private subnets (proper separation)
            # 2. Public subnets should not exceed 50% of total subnets
            # 3. Private subnets should exist for sensitive workloads
            
            has_both_types = public_count > 0 and private_count > 0
            public_percentage = (public_count / total_subnets * 100) if total_subnets > 0 else 0
            proper_ratio = public_percentage <= 50
            
            is_compliant = has_both_types and proper_ratio and private_count >= 1
            
            if is_compliant:
                # Proper subnet separation - COMPLIANT
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'VPC_SubnetArchitecture',
                    'resource_id': vpc_id,
                    'status': 'COMPLIANT',
                    'compliance_status': 'PASS',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Maintain proper subnet separation'),
                    'details': {
                        'vpc_id': vpc_id,
                        'total_subnets': total_subnets,
                        'public_subnets_count': public_count,
                        'private_subnets_count': private_count,
                        'public_percentage': round(public_percentage, 2),
                        'has_both_subnet_types': has_both_types,
                        'proper_ratio': proper_ratio,
                        'public_subnets': public_subnets,
                        'private_subnets': private_subnets
                    }
                }
            else:
                # Improper subnet separation - NON_COMPLIANT
                issues = []
                if not has_both_types:
                    if public_count == 0:
                        issues.append('No public subnets found')
                    if private_count == 0:
                        issues.append('No private subnets found')
                if not proper_ratio:
                    issues.append(f'Too many public subnets ({public_percentage:.1f}% of total)')
                if private_count == 0:
                    issues.append('No private subnets for secure workloads')
                
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'VPC_SubnetArchitecture',
                    'resource_id': vpc_id,
                    'status': 'NON_COMPLIANT',
                    'compliance_status': 'FAIL',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                    'recommendation': 'Implement proper separation between private and public subnets',
                    'details': {
                        'vpc_id': vpc_id,
                        'total_subnets': total_subnets,
                        'public_subnets_count': public_count,
                        'private_subnets_count': private_count,
                        'public_percentage': round(public_percentage, 2),
                        'has_both_subnet_types': has_both_types,
                        'proper_ratio': proper_ratio,
                        'issues': issues,
                        'public_subnets': public_subnets,
                        'private_subnets': private_subnets
                    }
                }
            
            findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in vpc_subnet_separate_private_public check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'VPC_SubnetArchitecture',
            'status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Review VPC subnet configuration'),
            'error': str(e)
        })
        
    return findings

def vpc_subnet_separate_private_public(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=vpc_subnet_separate_private_public_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = vpc_subnet_separate_private_public(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

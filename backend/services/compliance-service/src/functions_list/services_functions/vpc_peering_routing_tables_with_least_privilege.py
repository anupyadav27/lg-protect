#!/usr/bin/env python3
"""
cis_4.0_aws - vpc_peering_routing_tables_with_least_privilege

Ensure routing tables for VPC peering are least access
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
        'compliance_name': 'cis_4.0_aws',
        'function_name': 'vpc_peering_routing_tables_with_least_privilege',
        'id': 'CIS-4.X',
        'name': 'VPC peering routing tables should follow least privilege',
        'description': 'Ensure routing tables for VPC peering are least access',
        'api_function': 'client = boto3.client("ec2")',
        'user_function': 'describe_vpc_peering_connections(), describe_route_tables()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Review and restrict VPC peering routing table entries to follow least privilege principle'
    }

COMPLIANCE_DATA = load_compliance_metadata('vpc_peering_routing_tables_with_least_privilege')

def vpc_peering_routing_tables_with_least_privilege_check(ec2_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for vpc_peering_routing_tables_with_least_privilege.
    
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
        # Get all VPC peering connections
        peering_response = ec2_client.describe_vpc_peering_connections()
        peering_connections = peering_response.get('VpcPeeringConnections', [])
        
        # Get all route tables
        route_tables_response = ec2_client.describe_route_tables()
        route_tables = route_tables_response.get('RouteTables', [])
        
        for peering_conn in peering_connections:
            peering_conn_id = peering_conn.get('VpcPeeringConnectionId')
            status = peering_conn.get('Status', {}).get('Code')
            
            # Only check active peering connections
            if status != 'active':
                continue
                
            # Find route tables that reference this peering connection
            associated_route_tables = []
            overly_broad_routes = []
            
            for route_table in route_tables:
                route_table_id = route_table.get('RouteTableId')
                vpc_id = route_table.get('VpcId')
                routes = route_table.get('Routes', [])
                
                for route in routes:
                    gateway_id = route.get('VpcPeeringConnectionId')
                    if gateway_id == peering_conn_id:
                        destination_cidr = route.get('DestinationCidrBlock')
                        
                        # Check if route is overly broad (0.0.0.0/0 or very large CIDR blocks)
                        is_overly_broad = False
                        if destination_cidr:
                            if destination_cidr == '0.0.0.0/0':
                                is_overly_broad = True
                            else:
                                # Check for very broad CIDR blocks (less than /16)
                                try:
                                    cidr_parts = destination_cidr.split('/')
                                    if len(cidr_parts) == 2:
                                        prefix_length = int(cidr_parts[1])
                                        if prefix_length < 16:  # Very broad network
                                            is_overly_broad = True
                                except ValueError:
                                    pass
                        
                        route_info = {
                            'route_table_id': route_table_id,
                            'vpc_id': vpc_id,
                            'destination_cidr': destination_cidr,
                            'is_overly_broad': is_overly_broad
                        }
                        
                        associated_route_tables.append(route_info)
                        if is_overly_broad:
                            overly_broad_routes.append(route_info)
            
            # Determine compliance based on whether there are overly broad routes
            has_least_privilege = len(overly_broad_routes) == 0
            
            status_value = 'COMPLIANT' if has_least_privilege else 'NON_COMPLIANT'
            compliance_status = 'PASS' if has_least_privilege else 'FAIL'
            
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'VPC_PEERING_CONNECTION',
                'resource_id': peering_conn_id,
                'status': status_value,
                'compliance_status': compliance_status,
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                'recommendation': COMPLIANCE_DATA.get('recommendation', 'Review and restrict VPC peering routing table entries to follow least privilege principle'),
                'details': {
                    'peering_connection_id': peering_conn_id,
                    'peering_status': status,
                    'accepter_vpc_id': peering_conn.get('AccepterVpcInfo', {}).get('VpcId'),
                    'requester_vpc_id': peering_conn.get('RequesterVpcInfo', {}).get('VpcId'),
                    'associated_route_tables_count': len(associated_route_tables),
                    'overly_broad_routes_count': len(overly_broad_routes),
                    'has_least_privilege': has_least_privilege,
                    'associated_route_tables': associated_route_tables,
                    'overly_broad_routes': overly_broad_routes
                }
            }
            
            findings.append(finding)
        
        # If no peering connections found, add informational finding
        if not peering_connections:
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'VPC_PEERING_CONNECTION',
                'resource_id': 'NO_PEERING_CONNECTIONS',
                'status': 'COMPLIANT',
                'compliance_status': 'PASS',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                'recommendation': 'No VPC peering connections found in this region',
                'details': {
                    'message': 'No VPC peering connections found',
                    'peering_connections_count': 0
                }
            }
            findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in vpc_peering_routing_tables_with_least_privilege check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'VPC_PEERING_CONNECTION',
            'status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Review and restrict VPC peering routing table entries to follow least privilege principle'),
            'error': str(e)
        })
        
    return findings

def vpc_peering_routing_tables_with_least_privilege(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=vpc_peering_routing_tables_with_least_privilege_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    args = setup_command_line_interface(COMPLIANCE_DATA)
    results = vpc_peering_routing_tables_with_least_privilege(
        profile_name=args.profile,
        region_name=args.region
    )
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

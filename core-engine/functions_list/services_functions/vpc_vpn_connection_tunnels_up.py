#!/usr/bin/env python3
"""
iso27001_2022_aws - vpc_vpn_connection_tunnels_up

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
        'function_name': 'vpc_vpn_connection_tunnels_up',
        'id': 'VPN-001',
        'name': 'VPC VPN Connection Tunnels Status',
        'description': 'Security mechanisms, service levels and service requirements of network services should be identified, implemented and monitored.',
        'api_function': 'client=boto3.client("ec2")',
        'user_function': 'describe_vpn_connections()',
        'risk_level': 'HIGH',
        'recommendation': 'Ensure VPN connections have at least one tunnel in UP state for network connectivity'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('vpc_vpn_connection_tunnels_up')

def vpc_vpn_connection_tunnels_up_check(ec2_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for vpc_vpn_connection_tunnels_up.
    
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
        # Describe all VPN connections
        response = ec2_client.describe_vpn_connections()
        vpn_connections = response.get('VpnConnections', [])
        
        if not vpn_connections:
            logger.info(f"No VPN connections found in region {region}")
            return findings
        
        for vpn in vpn_connections:
            vpn_id = vpn.get('VpnConnectionId', 'Unknown')
            vpn_state = vpn.get('State', 'Unknown')
            vpn_type = vpn.get('Type', 'Unknown')
            customer_gateway_id = vpn.get('CustomerGatewayId', 'Unknown')
            vpn_gateway_id = vpn.get('VpnGatewayId', 'Unknown')
            transit_gateway_id = vpn.get('TransitGatewayId', 'Unknown')
            
            # Skip deleted or deleting VPN connections
            if vpn_state in ['deleted', 'deleting']:
                logger.debug(f"Skipping VPN connection {vpn_id} in state {vpn_state}")
                continue
            
            # Get VPN connection options
            options = vpn.get('Options', {})
            static_routes_only = options.get('StaticRoutesOnly', False)
            
            # Analyze tunnel states
            vgw_telemetry = vpn.get('VgwTelemetry', [])
            tunnel_states = []
            tunnels_up = 0
            tunnels_down = 0
            
            for tunnel in vgw_telemetry:
                tunnel_state = tunnel.get('Status', 'Unknown')
                tunnel_ip = tunnel.get('OutsideIpAddress', 'Unknown')
                last_status_change = tunnel.get('LastStatusChange', 'Unknown')
                status_message = tunnel.get('StatusMessage', 'Unknown')
                accepted_route_count = tunnel.get('AcceptedRouteCount', 0)
                
                tunnel_info = {
                    'tunnel_ip': tunnel_ip,
                    'status': tunnel_state,
                    'last_status_change': str(last_status_change),
                    'status_message': status_message,
                    'accepted_route_count': accepted_route_count
                }
                tunnel_states.append(tunnel_info)
                
                if tunnel_state == 'UP':
                    tunnels_up += 1
                else:
                    tunnels_down += 1
            
            # VPN connection is compliant if at least one tunnel is UP
            is_compliant = tunnels_up > 0
            
            if is_compliant:
                # At least one tunnel is UP - COMPLIANT
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'VPN_Connection',
                    'resource_id': f"{vpn_id}",
                    'status': 'COMPLIANT',
                    'compliance_status': 'PASS',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Maintain tunnel connectivity'),
                    'details': {
                        'vpn_connection_id': vpn_id,
                        'vpn_state': vpn_state,
                        'vpn_type': vpn_type,
                        'customer_gateway_id': customer_gateway_id,
                        'vpn_gateway_id': vpn_gateway_id,
                        'transit_gateway_id': transit_gateway_id,
                        'static_routes_only': static_routes_only,
                        'total_tunnels': len(vgw_telemetry),
                        'tunnels_up': tunnels_up,
                        'tunnels_down': tunnels_down,
                        'tunnel_states': tunnel_states,
                        'has_connectivity': True
                    }
                }
            else:
                # No tunnels are UP - NON_COMPLIANT
                issues = []
                if tunnels_down == len(vgw_telemetry):
                    issues.append('All tunnels are DOWN')
                elif tunnels_up == 0:
                    issues.append('No tunnels in UP state')
                
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'VPN_Connection',
                    'resource_id': f"{vpn_id}",
                    'status': 'NON_COMPLIANT',
                    'compliance_status': 'FAIL',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                    'recommendation': 'Troubleshoot and restore VPN tunnel connectivity',
                    'details': {
                        'vpn_connection_id': vpn_id,
                        'vpn_state': vpn_state,
                        'vpn_type': vpn_type,
                        'customer_gateway_id': customer_gateway_id,
                        'vpn_gateway_id': vpn_gateway_id,
                        'transit_gateway_id': transit_gateway_id,
                        'static_routes_only': static_routes_only,
                        'total_tunnels': len(vgw_telemetry),
                        'tunnels_up': tunnels_up,
                        'tunnels_down': tunnels_down,
                        'tunnel_states': tunnel_states,
                        'has_connectivity': False,
                        'issues': issues
                    }
                }
            
            findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in vpc_vpn_connection_tunnels_up check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'VPN_Connection',
            'status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Review VPN connection configuration'),
            'error': str(e)
        })
        
    return findings

def vpc_vpn_connection_tunnels_up(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=vpc_vpn_connection_tunnels_up_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = vpc_vpn_connection_tunnels_up(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

#!/usr/bin/env python3
"""
iso27001_2022_aws - directconnect_virtual_interface_redundancy

Information processing facilities should be implemented with redundancy sufficient to meet availability
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
                    'recommendation': entry.get('Recommendation', 'Implement redundant virtual interfaces for availability')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'iso27001_2022_aws',
        'function_name': 'directconnect_virtual_interface_redundancy',
        'id': 'A.8.14',
        'name': 'Redundancy of information processing facilities',
        'description': 'Information processing facilities should be implemented with redundancy sufficient to meet availability',
        'api_function': 'client=boto3.client(\'directconnect\')',
        'user_function': 'describe_virtual_interfaces()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Implement redundant virtual interfaces for availability'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('directconnect_virtual_interface_redundancy')

def directconnect_virtual_interface_redundancy_check(directconnect_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for directconnect_virtual_interface_redundancy.
    
    Args:
        directconnect_client: Boto3 DirectConnect client (auto-created by framework)
        region (str): AWS region (auto-managed by framework)
        profile (str): AWS profile name (auto-managed by framework)
        logger: Logger instance (auto-configured by framework)
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    try:
        # Get all virtual interfaces
        response = directconnect_client.describe_virtual_interfaces()
        virtual_interfaces = response.get('virtualInterfaces', [])
        
        if not virtual_interfaces:
            # No virtual interfaces found
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'DirectConnect',
                'resource_id': f'directconnect-check-{region}',
                'status': 'COMPLIANT',
                'compliance_status': 'PASS',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                'recommendation': 'No DirectConnect virtual interfaces found',
                'details': {
                    'total_virtual_interfaces': 0
                }
            }
            findings.append(finding)
            return findings
        
        # Group virtual interfaces by connection and VLAN
        connection_groups = {}
        
        for vi in virtual_interfaces:
            connection_id = vi.get('connectionId', 'unknown')
            vlan = vi.get('vlan', 0)
            vi_state = vi.get('virtualInterfaceState', 'unknown')
            vi_type = vi.get('virtualInterfaceType', 'unknown')
            vi_id = vi.get('virtualInterfaceId', 'unknown')
            
            # Only consider active virtual interfaces
            if vi_state not in ['available', 'up']:
                continue
                
            # Group by connection for redundancy analysis
            if connection_id not in connection_groups:
                connection_groups[connection_id] = []
            
            connection_groups[connection_id].append({
                'virtualInterfaceId': vi_id,
                'vlan': vlan,
                'state': vi_state,
                'type': vi_type,
                'bgpAsn': vi.get('bgpAsn'),
                'location': vi.get('location', 'unknown')
            })
        
        # Check for redundancy
        total_connections = len(connection_groups)
        active_vis = sum(len(vis) for vis in connection_groups.values())
        
        # Redundancy check: Should have multiple connections for redundancy
        is_redundant = total_connections >= 2
        
        # Additional check: Should have virtual interfaces in different locations for geographic redundancy
        locations = set()
        for connection_vis in connection_groups.values():
            for vi in connection_vis:
                if vi['location'] != 'unknown':
                    locations.add(vi['location'])
        
        has_geographic_redundancy = len(locations) >= 2
        
        # Determine compliance status
        if is_redundant and has_geographic_redundancy:
            status = 'COMPLIANT'
            compliance_status = 'PASS'
            recommendation = 'DirectConnect virtual interfaces have proper redundancy'
        elif is_redundant:
            status = 'NON_COMPLIANT'
            compliance_status = 'FAIL'
            recommendation = 'Consider implementing geographic redundancy across multiple locations'
        else:
            status = 'NON_COMPLIANT'
            compliance_status = 'FAIL'
            recommendation = 'Implement redundant DirectConnect connections for high availability'
        
        finding = {
            'region': region,
            'profile': profile,
            'resource_type': 'DirectConnect',
            'resource_id': f'directconnect-redundancy-{region}',
            'status': status,
            'compliance_status': compliance_status,
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': recommendation,
            'details': {
                'total_connections': total_connections,
                'total_active_virtual_interfaces': active_vis,
                'is_redundant': is_redundant,
                'has_geographic_redundancy': has_geographic_redundancy,
                'unique_locations': list(locations),
                'connection_details': connection_groups
            }
        }
        
        findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in directconnect_virtual_interface_redundancy check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'DirectConnect',
            'resource_id': f'directconnect-error-{region}',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Implement redundant virtual interfaces for availability'),
            'error': str(e)
        })
        
    return findings

def directconnect_virtual_interface_redundancy(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=directconnect_virtual_interface_redundancy_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = directconnect_virtual_interface_redundancy(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

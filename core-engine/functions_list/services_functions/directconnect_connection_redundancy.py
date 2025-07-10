#!/usr/bin/env python3
"""
iso27001_2022_aws - directconnect_connection_redundancy

Network controls should be implemented to ensure the protection of data in networks and the protection of connected services and applications.
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
        'function_name': 'directconnect_connection_redundancy',
        'id': 'ISO-27001-2022-A.13.1',
        'name': 'Network Controls',
        'description': 'Network controls should be implemented to ensure the protection of data in networks and the protection of connected services and applications.',
        'api_function': 'client = boto3.client(\'directconnect\')',
        'user_function': 'describe_connections()',
        'risk_level': 'HIGH',
        'recommendation': 'Implement redundant Direct Connect connections to ensure network availability and resilience'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('directconnect_connection_redundancy')

def directconnect_connection_redundancy_check(directconnect_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for directconnect_connection_redundancy.
    
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
        # Get all Direct Connect connections
        response = directconnect_client.describe_connections()
        connections = response.get('connections', [])
        
        if not connections:
            # No Direct Connect connections found
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'DirectConnect',
                'resource_id': f'no-connections-{region}',
                'status': 'NON_COMPLIANT',
                'compliance_status': 'FAIL',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                'recommendation': 'No Direct Connect connections found. Consider implementing Direct Connect for dedicated network connectivity.',
                'details': {
                    'connections_count': 0,
                    'message': 'No Direct Connect connections found in this region'
                }
            }
            findings.append(finding)
            return findings
        
        # Analyze connections by location and state for redundancy
        location_groups = {}
        total_active_connections = 0
        
        for connection in connections:
            connection_id = connection.get('connectionId', 'unknown')
            connection_name = connection.get('connectionName', 'unknown')
            location = connection.get('location', 'unknown')
            state = connection.get('connectionState', 'unknown')
            bandwidth = connection.get('bandwidth', 'unknown')
            
            # Group connections by location
            if location not in location_groups:
                location_groups[location] = []
            
            connection_details = {
                'connection_id': connection_id,
                'connection_name': connection_name,
                'state': state,
                'bandwidth': bandwidth,
                'location': location
            }
            
            location_groups[location].append(connection_details)
            
            # Count active connections
            if state in ['available', 'requested', 'pending']:
                total_active_connections += 1
        
        # Check for redundancy
        redundant_locations = []
        single_connection_locations = []
        
        for location, conns in location_groups.items():
            active_conns_in_location = [c for c in conns if c['state'] in ['available', 'requested', 'pending']]
            
            if len(active_conns_in_location) >= 2:
                redundant_locations.append({
                    'location': location,
                    'active_connections': len(active_conns_in_location),
                    'connections': active_conns_in_location
                })
            elif len(active_conns_in_location) == 1:
                single_connection_locations.append({
                    'location': location,
                    'active_connections': len(active_conns_in_location),
                    'connections': active_conns_in_location
                })
        
        # Determine overall compliance status
        if len(redundant_locations) > 0 or (len(location_groups) >= 2 and total_active_connections >= 2):
            # Has redundancy either in same location or across locations
            status = 'COMPLIANT'
            compliance_status = 'PASS'
            risk_level = 'LOW'
            recommendation = 'Direct Connect redundancy is properly configured'
        elif total_active_connections >= 2:
            # Multiple connections but need to verify they provide redundancy
            status = 'COMPLIANT'
            compliance_status = 'PASS'
            risk_level = 'MEDIUM'
            recommendation = 'Multiple Direct Connect connections found. Verify they provide adequate redundancy.'
        else:
            # Insufficient redundancy
            status = 'NON_COMPLIANT'
            compliance_status = 'FAIL'
            risk_level = COMPLIANCE_DATA.get('risk_level', 'HIGH')
            recommendation = COMPLIANCE_DATA.get('recommendation', 'Implement redundant Direct Connect connections')
        
        finding = {
            'region': region,
            'profile': profile,
            'resource_type': 'DirectConnect',
            'resource_id': f'directconnect-redundancy-{region}',
            'status': status,
            'compliance_status': compliance_status,
            'risk_level': risk_level,
            'recommendation': recommendation,
            'details': {
                'total_connections': len(connections),
                'total_active_connections': total_active_connections,
                'total_locations': len(location_groups),
                'redundant_locations': redundant_locations,
                'single_connection_locations': single_connection_locations,
                'all_connections': connections
            }
        }
        
        findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in directconnect_connection_redundancy check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'DirectConnect',
            'resource_id': f'error-check-{region}',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Implement redundant Direct Connect connections'),
            'error': str(e)
        })
        
    return findings

def directconnect_connection_redundancy(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=directconnect_connection_redundancy_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = directconnect_connection_redundancy(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

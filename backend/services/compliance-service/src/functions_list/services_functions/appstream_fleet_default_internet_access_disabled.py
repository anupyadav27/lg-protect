#!/usr/bin/env python3
"""
iso27001_2022_aws - appstream_fleet_default_internet_access_disabled

Information stored on, processed by or accessible via user endpoint devices should be protected.
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
                    'risk_level': entry.get('Risk Level', 'MEDIUM'),
                    'recommendation': entry.get('Recommendation', 'Review and remediate as needed')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'iso27001_2022_aws',
        'function_name': 'appstream_fleet_default_internet_access_disabled',
        'id': 'A.8.2',
        'name': 'Information stored on, processed by or accessible via user endpoint devices should be protected',
        'description': 'Information stored on, processed by or accessible via user endpoint devices should be protected.',
        'api_function': 'client=boto3.client(\'appstream\')',
        'user_function': 'describe_fleets()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Disable default internet access for AppStream fleets to protect endpoint devices'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('appstream_fleet_default_internet_access_disabled')

def appstream_fleet_default_internet_access_disabled_check(appstream_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for appstream_fleet_default_internet_access_disabled.
    
    Args:
        appstream_client: Boto3 appstream service client (auto-created by framework)
        region (str): AWS region (auto-managed by framework)
        profile (str): AWS profile name (auto-managed by framework)
        logger: Logger instance (auto-configured by framework)
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    try:
        # Get all AppStream fleets
        fleets_response = appstream_client.describe_fleets()
        fleets = fleets_response.get('Fleets', [])
        
        if not fleets:
            # No fleets found - create a single finding indicating no resources
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'AppStream Fleet',
                'resource_id': f'no-fleets-{region}',
                'status': 'COMPLIANT',
                'compliance_status': 'PASS',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                'recommendation': COMPLIANCE_DATA.get('recommendation', 'Disable default internet access for AppStream fleets'),
                'details': {
                    'message': 'No AppStream fleets found in this region',
                    'fleet_count': 0
                }
            }
            findings.append(finding)
            return findings
        
        # Check each fleet for internet access configuration
        for fleet in fleets:
            fleet_name = fleet.get('Name')
            fleet_arn = fleet.get('Arn')
            fleet_state = fleet.get('State', 'Unknown')
            
            # Check if default internet access is enabled
            enable_default_internet_access = fleet.get('EnableDefaultInternetAccess', True)  # Default is True
            
            # Fleet is compliant if default internet access is disabled
            if not enable_default_internet_access:
                status = 'COMPLIANT'
                compliance_status = 'PASS'
                message = f'Default internet access is disabled for fleet {fleet_name}'
            else:
                status = 'NON_COMPLIANT'
                compliance_status = 'FAIL'
                message = f'Default internet access is enabled for fleet {fleet_name}'
            
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'AppStream Fleet',
                'resource_id': fleet_arn or fleet_name,
                'status': status,
                'compliance_status': compliance_status,
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                'recommendation': COMPLIANCE_DATA.get('recommendation', 'Disable default internet access for AppStream fleets'),
                'details': {
                    'fleet_name': fleet_name,
                    'fleet_arn': fleet_arn,
                    'fleet_state': fleet_state,
                    'enable_default_internet_access': enable_default_internet_access,
                    'instance_type': fleet.get('InstanceType'),
                    'compute_capacity': fleet.get('ComputeCapacity', {}),
                    'message': message
                }
            }
            findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in appstream_fleet_default_internet_access_disabled check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'AppStream Fleet',
            'resource_id': f'error-{region}',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Disable default internet access for AppStream fleets'),
            'error': str(e)
        })
        
    return findings

def appstream_fleet_default_internet_access_disabled(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=appstream_fleet_default_internet_access_disabled_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = appstream_fleet_default_internet_access_disabled(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

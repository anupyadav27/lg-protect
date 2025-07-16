#!/usr/bin/env python3
"""
aws_well_architected_framework_security_pillar_aws - appstream_fleet_session_idle_disconnect_timeout

Integrate access controls with operator and application lifecycle and your centralized federation provider.
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
        'compliance_name': 'aws_well_architected_framework_security_pillar_aws',
        'function_name': 'appstream_fleet_session_idle_disconnect_timeout',
        'id': 'SEC-07',
        'name': 'Session timeout configuration',
        'description': 'Integrate access controls with operator and application lifecycle and your centralized federation provider.',
        'api_function': 'client=boto3.client(\'appstream\')',
        'user_function': 'describe_fleets()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Configure appropriate session idle disconnect timeout for AppStream fleets'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('appstream_fleet_session_idle_disconnect_timeout')

def appstream_fleet_session_idle_disconnect_timeout_check(appstream_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for appstream_fleet_session_idle_disconnect_timeout.
    
    Args:
        appstream_client: Boto3 appstream service client (auto-created by framework)
        region (str): AWS region (auto-managed by framework)
        profile (str): AWS profile name (auto-managed by framework)
        logger: Logger instance (auto-configured by framework)
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    # Define acceptable idle disconnect timeout range (in minutes)
    MIN_TIMEOUT = 5   # Minimum 5 minutes
    MAX_TIMEOUT = 60  # Maximum 60 minutes for security
    
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
                'recommendation': COMPLIANCE_DATA.get('recommendation', 'Configure appropriate session idle disconnect timeout'),
                'details': {
                    'message': 'No AppStream fleets found in this region',
                    'fleet_count': 0
                }
            }
            findings.append(finding)
            return findings
        
        # Check each fleet for session timeout configuration
        for fleet in fleets:
            fleet_name = fleet.get('Name')
            fleet_arn = fleet.get('Arn')
            fleet_state = fleet.get('State', 'Unknown')
            
            # Get session script details which contain timeout settings
            session_script = fleet.get('SessionScript', {})
            idle_disconnect_timeout = fleet.get('IdleDisconnectTimeoutInSeconds')
            disconnect_timeout = fleet.get('DisconnectTimeoutInSeconds')
            max_user_duration = fleet.get('MaxUserDurationInSeconds')
            
            # Convert seconds to minutes for evaluation
            idle_timeout_minutes = idle_disconnect_timeout / 60 if idle_disconnect_timeout else None
            
            # Determine compliance based on timeout configuration
            is_compliant = True
            compliance_issues = []
            
            if idle_disconnect_timeout is None:
                is_compliant = False
                compliance_issues.append('Idle disconnect timeout is not configured')
            elif idle_timeout_minutes < MIN_TIMEOUT or idle_timeout_minutes > MAX_TIMEOUT:
                is_compliant = False
                compliance_issues.append(f'Idle disconnect timeout ({idle_timeout_minutes:.1f} min) is outside recommended range ({MIN_TIMEOUT}-{MAX_TIMEOUT} min)')
            
            if is_compliant:
                status = 'COMPLIANT'
                compliance_status = 'PASS'
                message = f'Session timeout is properly configured for fleet {fleet_name}'
            else:
                status = 'NON_COMPLIANT'
                compliance_status = 'FAIL'
                message = f'Session timeout issues found for fleet {fleet_name}: {", ".join(compliance_issues)}'
            
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'AppStream Fleet',
                'resource_id': fleet_arn or fleet_name,
                'status': status,
                'compliance_status': compliance_status,
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                'recommendation': COMPLIANCE_DATA.get('recommendation', 'Configure appropriate session idle disconnect timeout'),
                'details': {
                    'fleet_name': fleet_name,
                    'fleet_arn': fleet_arn,
                    'fleet_state': fleet_state,
                    'idle_disconnect_timeout_seconds': idle_disconnect_timeout,
                    'idle_disconnect_timeout_minutes': idle_timeout_minutes,
                    'disconnect_timeout_seconds': disconnect_timeout,
                    'max_user_duration_seconds': max_user_duration,
                    'recommended_range_minutes': f'{MIN_TIMEOUT}-{MAX_TIMEOUT}',
                    'compliance_issues': compliance_issues,
                    'message': message
                }
            }
            findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in appstream_fleet_session_idle_disconnect_timeout check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'AppStream Fleet',
            'resource_id': f'error-{region}',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Configure appropriate session idle disconnect timeout'),
            'error': str(e)
        })
        
    return findings

def appstream_fleet_session_idle_disconnect_timeout(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=appstream_fleet_session_idle_disconnect_timeout_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = appstream_fleet_session_idle_disconnect_timeout(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

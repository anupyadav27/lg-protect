#!/usr/bin/env python3
"""
aws_well_architected_framework_security_pillar_aws - appstream_fleet_maximum_session_duration

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
        'function_name': 'appstream_fleet_maximum_session_duration',
        'id': 'SEC-07',
        'name': 'Maximum session duration configuration',
        'description': 'Integrate access controls with operator and application lifecycle and your centralized federation provider.',
        'api_function': 'client=boto3.client(\'appstream\')',
        'user_function': 'describe_fleets()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Configure appropriate maximum session duration for AppStream fleets'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('appstream_fleet_maximum_session_duration')

def appstream_fleet_maximum_session_duration_check(appstream_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for appstream_fleet_maximum_session_duration.
    
    Args:
        appstream_client: Boto3 appstream service client (auto-created by framework)
        region (str): AWS region (auto-managed by framework)
        profile (str): AWS profile name (auto-managed by framework)
        logger: Logger instance (auto-configured by framework)
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    # Define acceptable maximum session duration range (in hours)
    MIN_DURATION_HOURS = 1   # Minimum 1 hour
    MAX_DURATION_HOURS = 8   # Maximum 8 hours for security
    
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
                'recommendation': COMPLIANCE_DATA.get('recommendation', 'Configure appropriate maximum session duration'),
                'details': {
                    'message': 'No AppStream fleets found in this region',
                    'fleet_count': 0
                }
            }
            findings.append(finding)
            return findings
        
        # Check each fleet for maximum session duration configuration
        for fleet in fleets:
            fleet_name = fleet.get('Name')
            fleet_arn = fleet.get('Arn')
            fleet_state = fleet.get('State', 'Unknown')
            
            # Get maximum user duration settings
            max_user_duration = fleet.get('MaxUserDurationInSeconds')
            disconnect_timeout = fleet.get('DisconnectTimeoutInSeconds')
            idle_disconnect_timeout = fleet.get('IdleDisconnectTimeoutInSeconds')
            
            # Convert seconds to hours for evaluation
            max_duration_hours = max_user_duration / 3600 if max_user_duration else None
            
            # Determine compliance based on maximum session duration configuration
            is_compliant = True
            compliance_issues = []
            
            if max_user_duration is None:
                is_compliant = False
                compliance_issues.append('Maximum session duration is not configured')
            elif max_duration_hours < MIN_DURATION_HOURS:
                is_compliant = False
                compliance_issues.append(f'Maximum session duration ({max_duration_hours:.1f} hours) is too short (minimum {MIN_DURATION_HOURS} hours)')
            elif max_duration_hours > MAX_DURATION_HOURS:
                is_compliant = False
                compliance_issues.append(f'Maximum session duration ({max_duration_hours:.1f} hours) exceeds recommended maximum ({MAX_DURATION_HOURS} hours)')
            
            if is_compliant:
                status = 'COMPLIANT'
                compliance_status = 'PASS'
                message = f'Maximum session duration is properly configured for fleet {fleet_name}'
            else:
                status = 'NON_COMPLIANT'
                compliance_status = 'FAIL'
                message = f'Maximum session duration issues found for fleet {fleet_name}: {", ".join(compliance_issues)}'
            
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'AppStream Fleet',
                'resource_id': fleet_arn or fleet_name,
                'status': status,
                'compliance_status': compliance_status,
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                'recommendation': COMPLIANCE_DATA.get('recommendation', 'Configure appropriate maximum session duration'),
                'details': {
                    'fleet_name': fleet_name,
                    'fleet_arn': fleet_arn,
                    'fleet_state': fleet_state,
                    'max_user_duration_seconds': max_user_duration,
                    'max_user_duration_hours': max_duration_hours,
                    'disconnect_timeout_seconds': disconnect_timeout,
                    'idle_disconnect_timeout_seconds': idle_disconnect_timeout,
                    'recommended_range_hours': f'{MIN_DURATION_HOURS}-{MAX_DURATION_HOURS}',
                    'compliance_issues': compliance_issues,
                    'message': message
                }
            }
            findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in appstream_fleet_maximum_session_duration check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'AppStream Fleet',
            'resource_id': f'error-{region}',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Configure appropriate maximum session duration'),
            'error': str(e)
        })
        
    return findings

def appstream_fleet_maximum_session_duration(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=appstream_fleet_maximum_session_duration_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = appstream_fleet_maximum_session_duration(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

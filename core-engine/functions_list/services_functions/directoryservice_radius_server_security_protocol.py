#!/usr/bin/env python3
"""
iso27001_2022_aws - directoryservice_radius_server_security_protocol

Cryptographic controls should be used in compliance with all relevant agreements, legislation and regulations.
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
        'function_name': 'directoryservice_radius_server_security_protocol',
        'id': 'ISO-27001-2022-A.10.1',
        'name': 'Cryptographic Controls',
        'description': 'Cryptographic controls should be used in compliance with all relevant agreements, legislation and regulations.',
        'api_function': 'client = boto3.client(\'ds\')',
        'user_function': 'describe_directories()',
        'risk_level': 'HIGH',
        'recommendation': 'Configure RADIUS server with secure authentication protocols (PAP, CHAP, MS-CHAPv2, EAP)'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('directoryservice_radius_server_security_protocol')

def directoryservice_radius_server_security_protocol_check(ds_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for directoryservice_radius_server_security_protocol.
    
    Args:
        ds_client: Boto3 Directory Service client (auto-created by framework)
        region (str): AWS region (auto-managed by framework)
        profile (str): AWS profile name (auto-managed by framework)
        logger: Logger instance (auto-configured by framework)
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    try:
        # Get all directories in the region
        response = ds_client.describe_directories()
        directories = response.get('DirectoryDescriptions', [])
        
        if not directories:
            # No directories found - create informational finding
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'DirectoryService',
                'resource_id': f'no-directories-{region}',
                'status': 'COMPLIANT',
                'compliance_status': 'PASS',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                'recommendation': 'No Directory Service instances found in this region',
                'details': {
                    'directories_count': 0,
                    'message': 'No directories found to check for RADIUS security protocol configuration'
                }
            }
            findings.append(finding)
            return findings
        
        for directory in directories:
            directory_id = directory.get('DirectoryId', 'unknown')
            directory_name = directory.get('Name', 'unknown')
            directory_type = directory.get('Type', 'unknown')
            
            # Check for RADIUS settings
            radius_status = directory.get('RadiusStatus', 'Disabled')
            radius_settings = directory.get('RadiusSettings', {})
            
            if radius_status != 'Completed' or not radius_settings:
                # RADIUS not configured
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'DirectoryService',
                    'resource_id': directory_id,
                    'status': 'NON_COMPLIANT',
                    'compliance_status': 'FAIL',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                    'recommendation': 'Configure RADIUS authentication for this directory',
                    'details': {
                        'directory_name': directory_name,
                        'directory_type': directory_type,
                        'radius_status': radius_status,
                        'radius_configured': False,
                        'issue': 'RADIUS is not configured'
                    }
                }
                findings.append(finding)
                continue
            
            # Check RADIUS authentication protocol
            auth_protocol = radius_settings.get('AuthenticationProtocol', 'unknown')
            
            # Secure authentication protocols
            secure_protocols = ['PAP', 'CHAP', 'MS-CHAPv2', 'EAP']
            
            # Determine compliance status based on authentication protocol
            if auth_protocol in secure_protocols:
                status = 'COMPLIANT'
                compliance_status = 'PASS'
                recommendation = f'RADIUS is configured with secure authentication protocol: {auth_protocol}'
            else:
                status = 'NON_COMPLIANT'
                compliance_status = 'FAIL'
                recommendation = COMPLIANCE_DATA.get('recommendation', 'Configure RADIUS server with secure authentication protocols (PAP, CHAP, MS-CHAPv2, EAP)')
            
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'DirectoryService',
                'resource_id': directory_id,
                'status': status,
                'compliance_status': compliance_status,
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                'recommendation': recommendation,
                'details': {
                    'directory_name': directory_name,
                    'directory_type': directory_type,
                    'radius_status': radius_status,
                    'authentication_protocol': auth_protocol,
                    'secure_protocols': secure_protocols,
                    'radius_server': radius_settings.get('RadiusServers', []),
                    'radius_port': radius_settings.get('RadiusPort', 'unknown'),
                    'radius_timeout': radius_settings.get('RadiusTimeout', 'unknown'),
                    'radius_retries': radius_settings.get('RadiusRetries', 'unknown')
                }
            }
            
            findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in directoryservice_radius_server_security_protocol check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'DirectoryService',
            'resource_id': f'error-check-{region}',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Configure RADIUS server with secure authentication protocols (PAP, CHAP, MS-CHAPv2, EAP)'),
            'error': str(e)
        })
        
    return findings

def directoryservice_radius_server_security_protocol(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=directoryservice_radius_server_security_protocol_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = directoryservice_radius_server_security_protocol(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

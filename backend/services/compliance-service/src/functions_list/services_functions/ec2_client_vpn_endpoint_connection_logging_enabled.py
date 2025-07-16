#!/usr/bin/env python3
"""
iso27001_2022_aws - ec2_client_vpn_endpoint_connection_logging_enabled

Logs that record activities, exceptions, faults and other relevant events should be produced, stored, protected and analysed.
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
                    'recommendation': entry.get('Recommendation', 'Enable connection logging for Client VPN endpoints to monitor user connections and activities')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'iso27001_2022_aws',
        'function_name': 'ec2_client_vpn_endpoint_connection_logging_enabled',
        'id': 'ISO-27001-2022-A.12.4',
        'name': 'Event Logging',
        'description': 'Logs that record activities, exceptions, faults and other relevant events should be produced, stored, protected and analysed.',
        'api_function': 'client=boto3.client(\'ec2\')',
        'user_function': 'describe_client_vpn_endpoints()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Enable connection logging for Client VPN endpoints to monitor user connections and activities'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('ec2_client_vpn_endpoint_connection_logging_enabled')

def check_client_vpn_connection_logging(endpoint: Dict[str, Any]) -> Dict[str, Any]:
    """
    Check if a Client VPN endpoint has connection logging enabled.
    
    Args:
        endpoint: Client VPN endpoint configuration
        
    Returns:
        dict: Analysis results with logging status and details
    """
    result = {
        'connection_logging_enabled': False,
        'cloudwatch_log_group': None,
        'cloudwatch_log_stream': None,
        'logging_config': {}
    }
    
    # Check for connection log options
    connection_log_options = endpoint.get('ConnectionLogOptions', {})
    
    if connection_log_options:
        enabled = connection_log_options.get('Enabled', False)
        result['connection_logging_enabled'] = enabled
        result['logging_config'] = connection_log_options
        
        if enabled:
            result['cloudwatch_log_group'] = connection_log_options.get('CloudwatchLogGroup')
            result['cloudwatch_log_stream'] = connection_log_options.get('CloudwatchLogStream')
    
    return result

def ec2_client_vpn_endpoint_connection_logging_enabled_check(ec2_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for ec2_client_vpn_endpoint_connection_logging_enabled.
    
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
        # Get all Client VPN endpoints
        response = ec2_client.describe_client_vpn_endpoints()
        endpoints = response.get('ClientVpnEndpoints', [])
        
        if not endpoints:
            # No Client VPN endpoints found
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'EC2ClientVPN',
                'resource_id': f'no-client-vpn-endpoints-{region}',
                'status': 'COMPLIANT',
                'compliance_status': 'PASS',
                'risk_level': 'LOW',
                'recommendation': 'No Client VPN endpoints found in this region',
                'details': {
                    'endpoints_count': 0,
                    'message': 'No Client VPN endpoints found to check for connection logging'
                }
            }
            findings.append(finding)
            return findings
        
        # Check each Client VPN endpoint for connection logging
        non_compliant_count = 0
        for endpoint in endpoints:
            endpoint_id = endpoint.get('ClientVpnEndpointId', 'unknown')
            endpoint_state = endpoint.get('Status', {}).get('Code', 'unknown')
            dns_name = endpoint.get('DnsName', 'unknown')
            
            # Check connection logging configuration
            logging_analysis = check_client_vpn_connection_logging(endpoint)
            
            if logging_analysis['connection_logging_enabled']:
                status = 'COMPLIANT'
                compliance_status = 'PASS'
                risk_level = 'LOW'
                recommendation = 'Client VPN endpoint has connection logging properly enabled'
            else:
                non_compliant_count += 1
                status = 'NON_COMPLIANT'
                compliance_status = 'FAIL'
                risk_level = COMPLIANCE_DATA.get('risk_level', 'MEDIUM')
                recommendation = COMPLIANCE_DATA.get('recommendation', 'Enable connection logging for Client VPN endpoint')
            
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'EC2ClientVPN',
                'resource_id': endpoint_id,
                'status': status,
                'compliance_status': compliance_status,
                'risk_level': risk_level,
                'recommendation': recommendation,
                'details': {
                    'client_vpn_endpoint_id': endpoint_id,
                    'endpoint_state': endpoint_state,
                    'dns_name': dns_name,
                    'connection_logging_enabled': logging_analysis['connection_logging_enabled'],
                    'cloudwatch_log_group': logging_analysis['cloudwatch_log_group'],
                    'cloudwatch_log_stream': logging_analysis['cloudwatch_log_stream'],
                    'logging_configuration': logging_analysis['logging_config'],
                    'creation_time': endpoint.get('CreationTime', '').isoformat() if endpoint.get('CreationTime') else None,
                    'server_certificate_arn': endpoint.get('ServerCertificateArn', ''),
                    'authentication_options': endpoint.get('AuthenticationOptions', []),
                    'security_note': 'Connection logging is essential for monitoring VPN access and detecting unauthorized usage'
                }
            }
            
            findings.append(finding)
        
        logger.info(f"Checked {len(endpoints)} Client VPN endpoints, found {non_compliant_count} without connection logging")
        
    except Exception as e:
        logger.error(f"Error in ec2_client_vpn_endpoint_connection_logging_enabled check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'EC2ClientVPN',
            'resource_id': f'error-check-{region}',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable connection logging for Client VPN endpoints'),
            'error': str(e)
        })
        
    return findings

def ec2_client_vpn_endpoint_connection_logging_enabled(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=ec2_client_vpn_endpoint_connection_logging_enabled_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = ec2_client_vpn_endpoint_connection_logging_enabled(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

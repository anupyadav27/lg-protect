#!/usr/bin/env python3
"""
iso27001_2022_aws - transfer_server_in_transit_encryption_enabled

Rules for the effective use of cryptography, including cryptographic key management, should be defined and implemented.
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
        'function_name': 'transfer_server_in_transit_encryption_enabled',
        'id': 'TFS-001',
        'name': 'Transfer Server In-Transit Encryption',
        'description': 'Rules for the effective use of cryptography, including cryptographic key management, should be defined and implemented.',
        'api_function': 'client=boto3.client("transfer")',
        'user_function': 'list_servers(), describe_server()',
        'risk_level': 'HIGH',
        'recommendation': 'Enable in-transit encryption for all Transfer Family servers'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('transfer_server_in_transit_encryption_enabled')

def transfer_server_in_transit_encryption_enabled_check(transfer_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for transfer_server_in_transit_encryption_enabled.
    
    Args:
        transfer_client: Boto3 Transfer client (auto-created by framework)
        region (str): AWS region (auto-managed by framework)
        profile (str): AWS profile name (auto-managed by framework)
        logger: Logger instance (auto-configured by framework)
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    try:
        # List all Transfer Family servers
        response = transfer_client.list_servers()
        servers = response.get('Servers', [])
        
        if not servers:
            logger.info(f"No Transfer Family servers found in region {region}")
            return findings
        
        for server in servers:
            server_id = server.get('ServerId', 'Unknown')
            server_arn = server.get('Arn', 'Unknown')
            server_state = server.get('State', 'Unknown')
            
            try:
                # Get detailed server information
                server_response = transfer_client.describe_server(ServerId=server_id)
                server_details = server_response.get('Server', {})
                
                protocols = server_details.get('Protocols', [])
                endpoint_type = server_details.get('EndpointType', 'Unknown')
                certificate = server_details.get('Certificate', '')
                domain = server_details.get('Domain', 'Unknown')
                
                # Check for encryption-enabled protocols and configurations
                has_secure_protocols = False
                has_certificate = bool(certificate)
                encryption_details = []
                
                # Check protocols for encryption support
                for protocol in protocols:
                    if protocol in ['SFTP', 'FTPS']:
                        has_secure_protocols = True
                        encryption_details.append(f"{protocol} (encrypted)")
                    elif protocol == 'FTP':
                        encryption_details.append(f"{protocol} (not encrypted)")
                
                # For FTPS, check if certificate is configured
                if 'FTPS' in protocols and has_certificate:
                    ftps_properly_configured = True
                elif 'FTPS' in protocols and not has_certificate:
                    ftps_properly_configured = False
                else:
                    ftps_properly_configured = True  # Not applicable if FTPS not used
                
                # Determine compliance
                # Server is compliant if:
                # 1. Uses only secure protocols (SFTP/FTPS), OR
                # 2. If using FTPS, has certificate configured
                is_compliant = (
                    has_secure_protocols and 
                    'FTP' not in protocols and 
                    ftps_properly_configured
                )
                
                if is_compliant:
                    # Server has proper encryption - COMPLIANT
                    finding = {
                        'region': region,
                        'profile': profile,
                        'resource_type': 'Transfer_Server',
                        'resource_id': f"{server_id}",
                        'status': 'COMPLIANT',
                        'compliance_status': 'PASS',
                        'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                        'recommendation': COMPLIANCE_DATA.get('recommendation', 'Maintain secure configuration'),
                        'details': {
                            'server_id': server_id,
                            'server_arn': server_arn,
                            'server_state': server_state,
                            'protocols': protocols,
                            'endpoint_type': endpoint_type,
                            'has_certificate': has_certificate,
                            'certificate': certificate if has_certificate else 'Not configured',
                            'domain': domain,
                            'encryption_details': encryption_details,
                            'secure_protocols_only': True
                        }
                    }
                else:
                    # Server has insecure configuration - NON_COMPLIANT
                    issues = []
                    if 'FTP' in protocols:
                        issues.append('FTP protocol enabled (unencrypted)')
                    if 'FTPS' in protocols and not has_certificate:
                        issues.append('FTPS enabled but no certificate configured')
                    if not has_secure_protocols:
                        issues.append('No secure protocols (SFTP/FTPS) enabled')
                    
                    finding = {
                        'region': region,
                        'profile': profile,
                        'resource_type': 'Transfer_Server',
                        'resource_id': f"{server_id}",
                        'status': 'NON_COMPLIANT',
                        'compliance_status': 'FAIL',
                        'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                        'recommendation': 'Configure server to use only secure protocols (SFTP/FTPS) and ensure proper certificates',
                        'details': {
                            'server_id': server_id,
                            'server_arn': server_arn,
                            'server_state': server_state,
                            'protocols': protocols,
                            'endpoint_type': endpoint_type,
                            'has_certificate': has_certificate,
                            'certificate': certificate if has_certificate else 'Not configured',
                            'domain': domain,
                            'encryption_details': encryption_details,
                            'secure_protocols_only': False,
                            'issues': issues
                        }
                    }
                
                findings.append(finding)
                
            except Exception as server_error:
                logger.error(f"Error describing Transfer server {server_id}: {server_error}")
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'Transfer_Server',
                    'resource_id': f"{server_id}",
                    'status': 'ERROR',
                    'compliance_status': 'ERROR',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                    'recommendation': 'Review Transfer server configuration',
                    'error': str(server_error),
                    'details': {
                        'server_id': server_id,
                        'server_arn': server_arn,
                        'server_state': server_state
                    }
                }
                findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in transfer_server_in_transit_encryption_enabled check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'Transfer_Server',
            'status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Review Transfer Family configuration'),
            'error': str(e)
        })
        
    return findings

def transfer_server_in_transit_encryption_enabled(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=transfer_server_in_transit_encryption_enabled_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = transfer_server_in_transit_encryption_enabled(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

#!/usr/bin/env python3
"""
pci_4.0_aws - dms_endpoint_ssl_enabled

Checks if AWS Database Migration Service (AWS DMS) endpoints are configured with an SSL connection
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
                    'recommendation': entry.get('Recommendation', 'Enable SSL for DMS endpoints')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'pci_4.0_aws',
        'function_name': 'dms_endpoint_ssl_enabled',
        'id': 'PCI-DSS-4.0-4.1',
        'name': 'Cryptographic Controls',
        'description': 'Checks if AWS Database Migration Service (AWS DMS) endpoints are configured with an SSL connection',
        'api_function': 'client=boto3.client(\'dms\')',
        'user_function': 'describe_endpoint()',
        'risk_level': 'HIGH',
        'recommendation': 'Enable SSL/TLS encryption for all DMS endpoints to protect data in transit'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('dms_endpoint_ssl_enabled')

def dms_endpoint_ssl_enabled_check(dms_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for dms_endpoint_ssl_enabled.
    
    Args:
        dms_client: Boto3 DMS client (auto-created by framework)
        region (str): AWS region (auto-managed by framework)
        profile (str): AWS profile name (auto-managed by framework)
        logger: Logger instance (auto-configured by framework)
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    try:
        # Get all DMS endpoints
        paginator = dms_client.get_paginator('describe_endpoints')
        
        for page in paginator.paginate():
            endpoints = page.get('Endpoints', [])
            
            if not endpoints:
                continue
                
            for endpoint in endpoints:
                endpoint_identifier = endpoint.get('EndpointIdentifier', 'unknown')
                endpoint_type = endpoint.get('EndpointType', 'unknown')
                engine_name = endpoint.get('EngineName', 'unknown')
                ssl_mode = endpoint.get('SslMode', 'none')
                
                # Check if SSL is enabled
                ssl_enabled = ssl_mode not in ['none', 'disable']
                
                # Determine compliance status
                if ssl_enabled:
                    status = 'COMPLIANT'
                    compliance_status = 'PASS'
                    risk_level = 'LOW'
                    recommendation = 'DMS endpoint has SSL/TLS properly configured'
                else:
                    status = 'NON_COMPLIANT'
                    compliance_status = 'FAIL'
                    risk_level = COMPLIANCE_DATA.get('risk_level', 'HIGH')
                    recommendation = COMPLIANCE_DATA.get('recommendation', 'Enable SSL/TLS for this DMS endpoint')
                
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'DMS Endpoint',
                    'resource_id': endpoint_identifier,
                    'status': status,
                    'compliance_status': compliance_status,
                    'risk_level': risk_level,
                    'recommendation': recommendation,
                    'details': {
                        'endpoint_identifier': endpoint_identifier,
                        'endpoint_type': endpoint_type,
                        'engine_name': engine_name,
                        'ssl_mode': ssl_mode,
                        'ssl_enabled': ssl_enabled,
                        'is_compliant': ssl_enabled,
                        'security_note': 'SSL/TLS encryption protects data in transit between databases'
                    }
                }
                
                findings.append(finding)
        
        # If no endpoints found, create an informational finding
        if not findings:
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'DMS Endpoint',
                'resource_id': f'no-endpoints-{region}',
                'status': 'COMPLIANT',
                'compliance_status': 'PASS',
                'risk_level': 'LOW',
                'recommendation': 'No DMS endpoints found in this region',
                'details': {
                    'endpoints_count': 0,
                    'message': 'No DMS endpoints found to check for SSL configuration'
                }
            }
            findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in dms_endpoint_ssl_enabled check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'DMS Endpoint',
            'resource_id': f'error-check-{region}',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable SSL for DMS endpoints'),
            'error': str(e)
        })
        
    return findings

def dms_endpoint_ssl_enabled(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=dms_endpoint_ssl_enabled_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = dms_endpoint_ssl_enabled(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

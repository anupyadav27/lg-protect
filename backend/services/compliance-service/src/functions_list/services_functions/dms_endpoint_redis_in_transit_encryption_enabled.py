#!/usr/bin/env python3
"""
iso27001_2022_aws - dms_endpoint_redis_in_transit_encryption_enabled

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
                    'recommendation': entry.get('Recommendation', 'Enable in-transit encryption for DMS Redis endpoints')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'iso27001_2022_aws',
        'function_name': 'dms_endpoint_redis_in_transit_encryption_enabled',
        'id': 'ISO-27001-2022-A.10.1',
        'name': 'Cryptographic Controls',
        'description': 'Rules for the effective use of cryptography, including cryptographic key management, should be defined and implemented.',
        'api_function': 'client=boto3.client(\'dms\')',
        'user_function': 'describe_endpoints()',
        'risk_level': 'HIGH',
        'recommendation': 'Enable in-transit encryption for DMS Redis endpoints to protect data in transit'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('dms_endpoint_redis_in_transit_encryption_enabled')

def dms_endpoint_redis_in_transit_encryption_enabled_check(dms_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for dms_endpoint_redis_in_transit_encryption_enabled.
    
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
        
        redis_endpoints_found = False
        
        for page in paginator.paginate():
            endpoints = page.get('Endpoints', [])
            
            for endpoint in endpoints:
                endpoint_identifier = endpoint.get('EndpointIdentifier', 'unknown')
                endpoint_type = endpoint.get('EndpointType', 'unknown')
                engine_name = endpoint.get('EngineName', 'unknown')
                
                # Only check Redis endpoints
                if engine_name.lower() == 'redis':
                    redis_endpoints_found = True
                    
                    # Check SSL/TLS configuration
                    ssl_mode = endpoint.get('SslMode', 'none')
                    
                    # Get Redis-specific settings
                    redis_settings = endpoint.get('RedisSettings', {})
                    ssl_security_protocol = redis_settings.get('SslSecurityProtocol', None)
                    auth_type = redis_settings.get('AuthType', 'none')
                    
                    # Determine if in-transit encryption is enabled
                    has_ssl_encryption = ssl_mode in ['require', 'verify-ca', 'verify-full']
                    has_redis_ssl = ssl_security_protocol in ['ssl-encryption', 'plaintext']
                    
                    # Check for proper encryption configuration
                    is_encrypted = has_ssl_encryption or (ssl_security_protocol == 'ssl-encryption')
                    
                    # Determine compliance status
                    if is_encrypted:
                        status = 'COMPLIANT'
                        compliance_status = 'PASS'
                        risk_level = 'LOW'
                        recommendation = 'DMS Redis endpoint has in-transit encryption properly configured'
                    else:
                        status = 'NON_COMPLIANT'
                        compliance_status = 'FAIL'
                        risk_level = COMPLIANCE_DATA.get('risk_level', 'HIGH')
                        recommendation = COMPLIANCE_DATA.get('recommendation', 'Enable in-transit encryption for this DMS Redis endpoint')
                    
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
                            'ssl_security_protocol': ssl_security_protocol,
                            'auth_type': auth_type,
                            'has_ssl_encryption': has_ssl_encryption,
                            'is_compliant': is_encrypted,
                            'security_note': 'In-transit encryption protects data while being transferred to/from Redis'
                        }
                    }
                    
                    findings.append(finding)
        
        # If no Redis endpoints found, create an informational finding
        if not redis_endpoints_found:
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'DMS Endpoint',
                'resource_id': f'no-redis-endpoints-{region}',
                'status': 'COMPLIANT',
                'compliance_status': 'PASS',
                'risk_level': 'LOW',
                'recommendation': 'No DMS Redis endpoints found in this region',
                'details': {
                    'endpoints_count': 0,
                    'message': 'No DMS Redis endpoints found to check for in-transit encryption'
                }
            }
            findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in dms_endpoint_redis_in_transit_encryption_enabled check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'DMS Endpoint',
            'resource_id': f'error-check-{region}',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable in-transit encryption for DMS Redis endpoints'),
            'error': str(e)
        })
        
    return findings

def dms_endpoint_redis_in_transit_encryption_enabled(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=dms_endpoint_redis_in_transit_encryption_enabled_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = dms_endpoint_redis_in_transit_encryption_enabled(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

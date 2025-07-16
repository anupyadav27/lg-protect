#!/usr/bin/env python3
"""
aws_foundational_security_best_practices_aws - lightsail_static_ip_unused

This control checks whether Lightsail static IP addresses are associated with instances to avoid unnecessary costs.
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
                    'risk_level': entry.get('Risk Level', 'LOW'),
                    'recommendation': entry.get('Recommendation', 'Release unused Lightsail static IP addresses')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'aws_foundational_security_best_practices_aws',
        'function_name': 'lightsail_static_ip_unused',
        'id': 'Lightsail.1',
        'name': 'Lightsail static IP addresses should be attached',
        'description': 'This control checks whether Lightsail static IP addresses are associated with instances to avoid unnecessary costs.',
        'api_function': 'client = boto3.client("lightsail")',
        'user_function': 'get_static_ips()',
        'risk_level': 'LOW',
        'recommendation': 'Release unused Lightsail static IP addresses'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('lightsail_static_ip_unused')

def lightsail_static_ip_unused_check(lightsail_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for lightsail_static_ip_unused.
    
    Args:
        lightsail_client: Boto3 Lightsail client (auto-created by framework)
        region (str): AWS region (auto-managed by framework)
        profile (str): AWS profile name (auto-managed by framework)
        logger: Logger instance (auto-configured by framework)
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    try:
        logger.info("Checking Lightsail static IPs for usage...")
        
        # Get all static IPs
        response = lightsail_client.get_static_ips()
        static_ips = response.get('staticIps', [])
        
        if not static_ips:
            logger.info("No Lightsail static IPs found in this region")
            return findings
        
        for static_ip in static_ips:
            ip_name = static_ip.get('name', 'Unknown')
            ip_address = static_ip.get('ipAddress', 'Unknown')
            attached_to = static_ip.get('attachedTo', None)
            is_attached = static_ip.get('isAttached', False)
            
            # Determine compliance status
            if is_attached and attached_to:
                status = 'COMPLIANT'
                compliance_status = 'PASS'
                message = f"Static IP is attached to {attached_to}"
            else:
                status = 'NON_COMPLIANT'
                compliance_status = 'FAIL'
                message = "Static IP is not attached to any instance"
            
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'Lightsail Static IP',
                'resource_id': ip_name,
                'status': status,
                'compliance_status': compliance_status,
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'LOW'),
                'recommendation': COMPLIANCE_DATA.get('recommendation', 'Release unused Lightsail static IP addresses'),
                'details': {
                    'static_ip_name': ip_name,
                    'ip_address': ip_address,
                    'is_attached': is_attached,
                    'attached_to': attached_to if attached_to else 'None',
                    'created_at': str(static_ip.get('createdAt', 'Unknown')),
                    'location': static_ip.get('location', {}).get('availabilityZone', 'Unknown'),
                    'resource_type': static_ip.get('resourceType', 'Unknown'),
                    'message': message
                }
            }
            
            findings.append(finding)
            
    except Exception as e:
        logger.error(f"Error in lightsail_static_ip_unused check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'Lightsail Static IP',
            'resource_id': 'Unknown',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'LOW'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Release unused Lightsail static IP addresses'),
            'error': str(e),
            'details': {
                'error_message': str(e),
                'check_type': 'lightsail_static_ip_unused'
            }
        })
        
    return findings

def lightsail_static_ip_unused(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=lightsail_static_ip_unused_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = lightsail_static_ip_unused(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

#!/usr/bin/env python3
"""
aws_foundational_security_best_practices_aws - lightsail_instance_public

This control checks whether Lightsail instances have public IP addresses when they should be private for security.
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
                    'recommendation': entry.get('Recommendation', 'Review public access for Lightsail instances')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'aws_foundational_security_best_practices_aws',
        'function_name': 'lightsail_instance_public',
        'id': 'Lightsail.2',
        'name': 'Lightsail instances should not have public IP addresses unless required',
        'description': 'This control checks whether Lightsail instances have public IP addresses when they should be private for security.',
        'api_function': 'client = boto3.client("lightsail")',
        'user_function': 'get_instances()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Review public access for Lightsail instances'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('lightsail_instance_public')

def lightsail_instance_public_check(lightsail_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for lightsail_instance_public.
    
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
        logger.info("Checking Lightsail instances for public access...")
        
        # Get all instances
        response = lightsail_client.get_instances()
        instances = response.get('instances', [])
        
        if not instances:
            logger.info("No Lightsail instances found in this region")
            return findings
        
        for instance in instances:
            instance_name = instance.get('name', 'Unknown')
            instance_state = instance.get('state', {}).get('name', 'Unknown')
            
            # Check networking configuration
            networking = instance.get('networking', {})
            public_ip = instance.get('publicIpAddress', None)
            private_ip = instance.get('privateIpAddress', None)
            
            # Check if instance has public IP
            has_public_ip = public_ip is not None and public_ip != ''
            
            # Check ports configuration for public access
            ports = networking.get('ports', [])
            has_public_ports = False
            public_port_details = []
            
            for port in ports:
                access_from = port.get('accessFrom', 'Unknown')
                if access_from == 'Anywhere (0.0.0.0/0)':
                    has_public_ports = True
                    public_port_details.append({
                        'port_range': f"{port.get('fromPort', 'Unknown')}-{port.get('toPort', 'Unknown')}",
                        'protocol': port.get('protocol', 'Unknown'),
                        'access_type': port.get('accessType', 'Unknown')
                    })
            
            # Determine compliance status
            # Flag instances with public IPs and open ports as potential security risks
            if has_public_ip and has_public_ports:
                status = 'NON_COMPLIANT'
                compliance_status = 'FAIL'
                message = f"Instance has public IP ({public_ip}) with open ports accessible from anywhere"
            elif has_public_ip:
                status = 'NON_COMPLIANT'
                compliance_status = 'FAIL'
                message = f"Instance has public IP ({public_ip}) but no public ports configured"
            elif has_public_ports:
                status = 'NON_COMPLIANT'
                compliance_status = 'FAIL'
                message = "Instance has ports open to public access but no public IP"
            else:
                status = 'COMPLIANT'
                compliance_status = 'PASS'
                message = "Instance does not have public access configured"
            
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'Lightsail Instance',
                'resource_id': instance_name,
                'status': status,
                'compliance_status': compliance_status,
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                'recommendation': COMPLIANCE_DATA.get('recommendation', 'Review public access for Lightsail instances'),
                'details': {
                    'instance_name': instance_name,
                    'instance_state': instance_state,
                    'public_ip_address': public_ip if public_ip else 'None',
                    'private_ip_address': private_ip if private_ip else 'None',
                    'has_public_ip': has_public_ip,
                    'has_public_ports': has_public_ports,
                    'public_port_details': public_port_details,
                    'blueprint_id': instance.get('blueprintId', 'Unknown'),
                    'bundle_id': instance.get('bundleId', 'Unknown'),
                    'created_at': str(instance.get('createdAt', 'Unknown')),
                    'location': instance.get('location', {}).get('availabilityZone', 'Unknown'),
                    'message': message
                }
            }
            
            findings.append(finding)
            
    except Exception as e:
        logger.error(f"Error in lightsail_instance_public check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'Lightsail Instance',
            'resource_id': 'Unknown',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Review public access for Lightsail instances'),
            'error': str(e),
            'details': {
                'error_message': str(e),
                'check_type': 'lightsail_instance_public'
            }
        })
        
    return findings

def lightsail_instance_public(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=lightsail_instance_public_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = lightsail_instance_public(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

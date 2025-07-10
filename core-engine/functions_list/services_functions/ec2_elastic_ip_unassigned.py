#!/usr/bin/env python3
"""
cisa_aws - ec2_elastic_ip_unassigned

Learn what is happening on your network, manage network and perimeter components, host and device components, data-at-rest and in-transit, and user behavior activities.
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
                    'recommendation': entry.get('Recommendation', 'Assign or release unassigned Elastic IP addresses')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'cisa_aws',
        'function_name': 'ec2_elastic_ip_unassigned',
        'id': 'your-data-2',
        'name': 'Your Data-2',
        'description': 'Learn what is happening on your network, manage network and perimeter components, host and device components, data-at-rest and in-transit, and user behavior activities.',
        'api_function': 'client = boto3.client(\'ec2\')',
        'user_function': 'describe_addresses()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Assign or release unassigned Elastic IP addresses to avoid unnecessary costs and security risks'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('ec2_elastic_ip_unassigned')

def ec2_elastic_ip_unassigned_check(ec2_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for ec2_elastic_ip_unassigned.
    
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
        # Get all Elastic IP addresses
        response = ec2_client.describe_addresses()
        addresses = response.get('Addresses', [])
        
        if not addresses:
            # No Elastic IPs found, create an informational finding
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'Elastic IP',
                'resource_id': f'no-eips-{region}',
                'status': 'COMPLIANT',
                'compliance_status': 'PASS',
                'risk_level': 'LOW',
                'recommendation': 'No Elastic IP addresses found in this region',
                'details': {
                    'eips_count': 0,
                    'message': 'No Elastic IP addresses found to check for assignment'
                }
            }
            findings.append(finding)
            return findings
        
        for address in addresses:
            allocation_id = address.get('AllocationId', 'unknown')
            public_ip = address.get('PublicIp', 'unknown')
            instance_id = address.get('InstanceId', None)
            network_interface_id = address.get('NetworkInterfaceId', None)
            association_id = address.get('AssociationId', None)
            domain = address.get('Domain', 'unknown')
            
            # Determine if the Elastic IP is assigned
            is_assigned = bool(instance_id or network_interface_id or association_id)
            
            # Determine compliance status
            if is_assigned:
                status = 'COMPLIANT'
                compliance_status = 'PASS'
                risk_level = 'LOW'
                recommendation = 'Elastic IP address is properly assigned'
            else:
                status = 'NON_COMPLIANT'
                compliance_status = 'FAIL'
                risk_level = COMPLIANCE_DATA.get('risk_level', 'MEDIUM')
                recommendation = COMPLIANCE_DATA.get('recommendation', 'Assign this Elastic IP address to a resource or release it')
            
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'Elastic IP',
                'resource_id': allocation_id,
                'status': status,
                'compliance_status': compliance_status,
                'risk_level': risk_level,
                'recommendation': recommendation,
                'details': {
                    'allocation_id': allocation_id,
                    'public_ip': public_ip,
                    'instance_id': instance_id or 'N/A',
                    'network_interface_id': network_interface_id or 'N/A',
                    'association_id': association_id or 'N/A',
                    'domain': domain,
                    'is_assigned': is_assigned,
                    'is_compliant': is_assigned,
                    'security_note': 'Unassigned Elastic IPs incur charges and may pose security risks'
                }
            }
            
            findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in ec2_elastic_ip_unassigned check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'Elastic IP',
            'resource_id': f'error-check-{region}',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Assign or release unassigned Elastic IP addresses'),
            'error': str(e)
        })
        
    return findings

def ec2_elastic_ip_unassigned(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=ec2_elastic_ip_unassigned_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = ec2_elastic_ip_unassigned(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

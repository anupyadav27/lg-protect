#!/usr/bin/env python3
"""
pci_3.2.1_aws - dms_instance_no_public_access

Without a mechanism to restrict access based on user's need to know, a user may unknowingly be granted access to cardholder data. Access control systems automate the process of restricting access and assigning privileges. Additionally, a default "deny-all" setting ensures no one is granted access until and unless a rule is established specifically granting such access.
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
                    'risk_level': entry.get('Risk Level', 'HIGH'),
                    'recommendation': entry.get('Recommendation', 'Ensure DMS replication instances are not publicly accessible')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'pci_3.2.1_aws',
        'function_name': 'dms_instance_no_public_access',
        'id': 'PCI-DSS-3.2.1-7.1',
        'name': 'Access Control Systems',
        'description': 'Without a mechanism to restrict access based on user\'s need to know, a user may unknowingly be granted access to cardholder data.',
        'api_function': 'client=boto3.client(\'dms\')',
        'user_function': 'describe_replication_instances()',
        'risk_level': 'HIGH',
        'recommendation': 'Ensure DMS replication instances are not publicly accessible to prevent unauthorized access'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('dms_instance_no_public_access')

def dms_instance_no_public_access_check(dms_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for dms_instance_no_public_access.
    
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
        # Get all DMS replication instances
        response = dms_client.describe_replication_instances()
        instances = response.get('ReplicationInstances', [])
        
        if not instances:
            # No replication instances found - this is compliant
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'DMS',
                'resource_id': f'no-instances-{region}',
                'status': 'COMPLIANT',
                'compliance_status': 'PASS',
                'risk_level': 'LOW',
                'recommendation': 'No DMS replication instances found in this region',
                'details': {
                    'instances_count': 0,
                    'message': 'No DMS replication instances found to check for public access'
                }
            }
            findings.append(finding)
            return findings
        
        for instance in instances:
            instance_id = instance.get('ReplicationInstanceIdentifier', 'unknown')
            instance_arn = instance.get('ReplicationInstanceArn', 'unknown')
            
            # Check if the instance is publicly accessible
            is_publicly_accessible = instance.get('PubliclyAccessible', False)
            
            # Determine compliance status
            if is_publicly_accessible:
                status = 'NON_COMPLIANT'
                compliance_status = 'FAIL'
                risk_level = COMPLIANCE_DATA.get('risk_level', 'HIGH')
                recommendation = COMPLIANCE_DATA.get('recommendation', 'Disable public access for DMS replication instance')
            else:
                status = 'COMPLIANT'
                compliance_status = 'PASS'
                risk_level = 'LOW'
                recommendation = 'DMS replication instance is not publicly accessible'
            
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'DMS',
                'resource_id': instance_id,
                'status': status,
                'compliance_status': compliance_status,
                'risk_level': risk_level,
                'recommendation': recommendation,
                'details': {
                    'instance_id': instance_id,
                    'instance_arn': instance_arn,
                    'instance_class': instance.get('ReplicationInstanceClass', 'unknown'),
                    'engine_version': instance.get('EngineVersion', 'unknown'),
                    'publicly_accessible': is_publicly_accessible,
                    'vpc_security_groups': instance.get('VpcSecurityGroups', []),
                    'subnet_group': instance.get('ReplicationSubnetGroup', {}),
                    'multi_az': instance.get('MultiAZ', False),
                    'status': instance.get('ReplicationInstanceStatus', 'unknown'),
                    'availability_zone': instance.get('AvailabilityZone', 'unknown'),
                    'secondary_availability_zone': instance.get('SecondaryAvailabilityZone', 'unknown'),
                    'allocated_storage': instance.get('AllocatedStorage', 0),
                    'auto_minor_version_upgrade': instance.get('AutoMinorVersionUpgrade', False)
                }
            }
            
            findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in dms_instance_no_public_access check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'DMS',
            'resource_id': f'error-check-{region}',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Ensure DMS replication instances are not publicly accessible'),
            'error': str(e)
        })
        
    return findings

def dms_instance_no_public_access(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=dms_instance_no_public_access_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = dms_instance_no_public_access(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

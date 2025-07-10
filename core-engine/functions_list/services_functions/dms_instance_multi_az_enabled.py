#!/usr/bin/env python3
"""
iso27001_2022_aws - dms_instance_multi_az_enabled

Information processing facilities should be implemented with redundancy sufficient to meet availability
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
                    'recommendation': entry.get('Recommendation', 'Enable Multi-AZ for DMS replication instances')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'iso27001_2022_aws',
        'function_name': 'dms_instance_multi_az_enabled',
        'id': 'ISO-27001-2022-A.17.1',
        'name': 'Planning Information Security Continuity',
        'description': 'Information processing facilities should be implemented with redundancy sufficient to meet availability',
        'api_function': 'client=boto3.client(\'dms\')',
        'user_function': 'describe_replication_instances()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Enable Multi-AZ deployment for DMS replication instances to ensure high availability'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('dms_instance_multi_az_enabled')

def dms_instance_multi_az_enabled_check(dms_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for dms_instance_multi_az_enabled.
    
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
        paginator = dms_client.get_paginator('describe_replication_instances')
        
        for page in paginator.paginate():
            replication_instances = page.get('ReplicationInstances', [])
            
            if not replication_instances:
                continue
                
            for instance in replication_instances:
                instance_identifier = instance.get('ReplicationInstanceIdentifier', 'unknown')
                instance_class = instance.get('ReplicationInstanceClass', 'unknown')
                engine_version = instance.get('EngineVersion', 'unknown')
                multi_az = instance.get('MultiAZ', False)
                instance_status = instance.get('ReplicationInstanceStatus', 'unknown')
                availability_zone = instance.get('AvailabilityZone', 'unknown')
                vpc_security_groups = instance.get('VpcSecurityGroups', [])
                
                # Determine compliance status
                if multi_az:
                    status = 'COMPLIANT'
                    compliance_status = 'PASS'
                    risk_level = 'LOW'
                    recommendation = 'DMS replication instance has Multi-AZ deployment enabled for high availability'
                else:
                    status = 'NON_COMPLIANT'
                    compliance_status = 'FAIL'
                    risk_level = COMPLIANCE_DATA.get('risk_level', 'MEDIUM')
                    recommendation = COMPLIANCE_DATA.get('recommendation', 'Enable Multi-AZ deployment for this DMS replication instance')
                
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'DMS Replication Instance',
                    'resource_id': instance_identifier,
                    'status': status,
                    'compliance_status': compliance_status,
                    'risk_level': risk_level,
                    'recommendation': recommendation,
                    'details': {
                        'replication_instance_identifier': instance_identifier,
                        'instance_class': instance_class,
                        'engine_version': engine_version,
                        'multi_az': multi_az,
                        'instance_status': instance_status,
                        'availability_zone': availability_zone,
                        'vpc_security_groups_count': len(vpc_security_groups),
                        'is_compliant': multi_az,
                        'security_note': 'Multi-AZ deployment provides automatic failover and high availability'
                    }
                }
                
                findings.append(finding)
        
        # If no replication instances found, create an informational finding
        if not findings:
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'DMS Replication Instance',
                'resource_id': f'no-instances-{region}',
                'status': 'COMPLIANT',
                'compliance_status': 'PASS',
                'risk_level': 'LOW',
                'recommendation': 'No DMS replication instances found in this region',
                'details': {
                    'instances_count': 0,
                    'message': 'No DMS replication instances found to check for Multi-AZ deployment'
                }
            }
            findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in dms_instance_multi_az_enabled check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'DMS Replication Instance',
            'resource_id': f'error-check-{region}',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable Multi-AZ for DMS replication instances'),
            'error': str(e)
        })
        
    return findings

def dms_instance_multi_az_enabled(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=dms_instance_multi_az_enabled_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = dms_instance_multi_az_enabled(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

#!/usr/bin/env python3
"""
kisa_isms_p_2023_korean_aws - dms_instance_minor_version_upgrade_enabled

소프트웨어, 운영체제, 보안시스템 등의 취약점으로 인한 침해사고를 예방하기 위하여 최신 패치를 적용하여야 한다. 다만 서비스 영향을 검토하여 최신 패치 적용이 어려울 경우 별도의 보완대책을 마련하여 이행하여야 한다.
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
                    'recommendation': entry.get('Recommendation', 'Enable automatic minor version upgrades for DMS instances')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'kisa_isms_p_2023_korean_aws',
        'function_name': 'dms_instance_minor_version_upgrade_enabled',
        'id': '2.8.3',
        'name': 'Vulnerability Management',
        'description': '소프트웨어, 운영체제, 보안시스템 등의 취약점으로 인한 침해사고를 예방하기 위하여 최신 패치를 적용하여야 한다.',
        'api_function': 'client=boto3.client(\'dms\')',
        'user_function': 'describe_replication_instances()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Enable automatic minor version upgrades for DMS replication instances to ensure security patches are applied'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('dms_instance_minor_version_upgrade_enabled')

def dms_instance_minor_version_upgrade_enabled_check(dms_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for dms_instance_minor_version_upgrade_enabled.
    
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
                auto_minor_version_upgrade = instance.get('AutoMinorVersionUpgrade', False)
                instance_status = instance.get('ReplicationInstanceStatus', 'unknown')
                availability_zone = instance.get('AvailabilityZone', 'unknown')
                
                # Determine compliance status
                if auto_minor_version_upgrade:
                    status = 'COMPLIANT'
                    compliance_status = 'PASS'
                    risk_level = 'LOW'
                    recommendation = 'DMS replication instance has automatic minor version upgrades enabled'
                else:
                    status = 'NON_COMPLIANT'
                    compliance_status = 'FAIL'
                    risk_level = COMPLIANCE_DATA.get('risk_level', 'MEDIUM')
                    recommendation = COMPLIANCE_DATA.get('recommendation', 'Enable automatic minor version upgrades for this DMS instance')
                
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
                        'auto_minor_version_upgrade': auto_minor_version_upgrade,
                        'instance_status': instance_status,
                        'availability_zone': availability_zone,
                        'is_compliant': auto_minor_version_upgrade,
                        'security_note': 'Automatic minor version upgrades ensure security patches are applied promptly'
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
                    'message': 'No DMS replication instances found to check for automatic minor version upgrades'
                }
            }
            findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in dms_instance_minor_version_upgrade_enabled check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'DMS Replication Instance',
            'resource_id': f'error-check-{region}',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable automatic minor version upgrades for DMS instances'),
            'error': str(e)
        })
        
    return findings

def dms_instance_minor_version_upgrade_enabled(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=dms_instance_minor_version_upgrade_enabled_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = dms_instance_minor_version_upgrade_enabled(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

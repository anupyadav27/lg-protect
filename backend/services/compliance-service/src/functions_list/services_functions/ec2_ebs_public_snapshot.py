#!/usr/bin/env python3
"""
cisa_aws - ec2_ebs_public_snapshot

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
                    'recommendation': entry.get('Recommendation', 'Remove public access from EBS snapshots')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'cisa_aws',
        'function_name': 'ec2_ebs_public_snapshot',
        'id': 'your-data-2',
        'name': 'Your Data-2',
        'description': 'Learn what is happening on your network, manage network and perimeter components, host and device components, data-at-rest and in-transit, and user behavior activities.',
        'api_function': 'client = boto3.client(\'ec2\')',
        'user_function': 'describe_snapshots()',
        'risk_level': 'HIGH',
        'recommendation': 'Remove public access from EBS snapshots to prevent unauthorized access'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('ec2_ebs_public_snapshot')

def ec2_ebs_public_snapshot_check(ec2_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for ec2_ebs_public_snapshot.
    
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
        # Get snapshots owned by this account
        paginator = ec2_client.get_paginator('describe_snapshots')
        
        for page in paginator.paginate(OwnerIds=['self']):
            snapshots = page.get('Snapshots', [])
            
            if not snapshots:
                continue
                
            for snapshot in snapshots:
                snapshot_id = snapshot.get('SnapshotId', 'unknown')
                volume_id = snapshot.get('VolumeId', 'unknown')
                volume_size = snapshot.get('VolumeSize', 0)
                state = snapshot.get('State', 'unknown')
                start_time = snapshot.get('StartTime', 'unknown')
                encrypted = snapshot.get('Encrypted', False)
                
                # Check if snapshot has public permissions
                try:
                    attrs_response = ec2_client.describe_snapshot_attribute(
                        SnapshotId=snapshot_id,
                        Attribute='createVolumePermission'
                    )
                    
                    create_volume_permissions = attrs_response.get('CreateVolumePermissions', [])
                    is_public = any(perm.get('Group') == 'all' for perm in create_volume_permissions)
                    
                    # Determine compliance status
                    if is_public:
                        status = 'NON_COMPLIANT'
                        compliance_status = 'FAIL'
                        risk_level = COMPLIANCE_DATA.get('risk_level', 'HIGH')
                        recommendation = COMPLIANCE_DATA.get('recommendation', 'Remove public access from this EBS snapshot')
                    else:
                        status = 'COMPLIANT'
                        compliance_status = 'PASS'
                        risk_level = 'LOW'
                        recommendation = 'EBS snapshot is not publicly accessible'
                    
                    finding = {
                        'region': region,
                        'profile': profile,
                        'resource_type': 'EBS Snapshot',
                        'resource_id': snapshot_id,
                        'status': status,
                        'compliance_status': compliance_status,
                        'risk_level': risk_level,
                        'recommendation': recommendation,
                        'details': {
                            'snapshot_id': snapshot_id,
                            'is_public': is_public,
                            'volume_id': volume_id,
                            'volume_size_gb': volume_size,
                            'state': state,
                            'start_time': str(start_time),
                            'encrypted': encrypted,
                            'create_volume_permissions': create_volume_permissions,
                            'is_compliant': not is_public,
                            'security_note': 'Public EBS snapshots can be accessed by anyone'
                        }
                    }
                    
                    findings.append(finding)
                    
                except Exception as attr_error:
                    logger.warning(f"Could not check attributes for snapshot {snapshot_id}: {attr_error}")
                    # Still create a finding indicating we couldn't check
                    finding = {
                        'region': region,
                        'profile': profile,
                        'resource_type': 'EBS Snapshot',
                        'resource_id': snapshot_id,
                        'status': 'ERROR',
                        'compliance_status': 'ERROR',
                        'risk_level': 'MEDIUM',
                        'recommendation': 'Unable to check snapshot permissions',
                        'details': {
                            'snapshot_id': snapshot_id,
                            'volume_id': volume_id,
                            'state': state,
                            'encrypted': encrypted,
                            'error': str(attr_error),
                            'note': 'Could not check snapshot permissions'
                        }
                    }
                    findings.append(finding)
        
        # If no snapshots found, create an informational finding
        if not findings:
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'EBS Snapshot',
                'resource_id': f'no-snapshots-{region}',
                'status': 'COMPLIANT',
                'compliance_status': 'PASS',
                'risk_level': 'LOW',
                'recommendation': 'No EBS snapshots found in this region',
                'details': {
                    'snapshots_count': 0,
                    'message': 'No EBS snapshots found to check for public access'
                }
            }
            findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in ec2_ebs_public_snapshot check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'EBS Snapshot',
            'resource_id': f'error-check-{region}',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Remove public access from EBS snapshots'),
            'error': str(e)
        })
        
    return findings

def ec2_ebs_public_snapshot(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=ec2_ebs_public_snapshot_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = ec2_ebs_public_snapshot(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

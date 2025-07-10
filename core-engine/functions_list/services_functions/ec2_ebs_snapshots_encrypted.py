#!/usr/bin/env python3
"""
cisa_aws - ec2_ebs_snapshots_encrypted

Learn how your data is protected.
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
                    'recommendation': entry.get('Recommendation', 'Enable EBS snapshot encryption')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'cisa_aws',
        'function_name': 'ec2_ebs_snapshots_encrypted',
        'id': 'your-data-1',
        'name': 'Your Data-1',
        'description': 'Learn how your data is protected.',
        'api_function': 'client = boto3.client(\'ec2\')',
        'user_function': 'describe_snapshots()',
        'risk_level': 'HIGH',
        'recommendation': 'Enable encryption for all EBS snapshots to protect data at rest'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('ec2_ebs_snapshots_encrypted')

def ec2_ebs_snapshots_encrypted_check(ec2_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for ec2_ebs_snapshots_encrypted.
    
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
                encrypted = snapshot.get('Encrypted', False)
                volume_id = snapshot.get('VolumeId', 'unknown')
                volume_size = snapshot.get('VolumeSize', 0)
                state = snapshot.get('State', 'unknown')
                start_time = snapshot.get('StartTime', 'unknown')
                progress = snapshot.get('Progress', 'unknown')
                
                # Determine compliance status
                if encrypted:
                    status = 'COMPLIANT'
                    compliance_status = 'PASS'
                    risk_level = 'LOW'
                    recommendation = 'EBS snapshot is properly encrypted'
                else:
                    status = 'NON_COMPLIANT'
                    compliance_status = 'FAIL'
                    risk_level = COMPLIANCE_DATA.get('risk_level', 'HIGH')
                    recommendation = COMPLIANCE_DATA.get('recommendation', 'Enable encryption for this EBS snapshot')
                
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
                        'encrypted': encrypted,
                        'volume_id': volume_id,
                        'volume_size_gb': volume_size,
                        'state': state,
                        'start_time': str(start_time),
                        'progress': progress,
                        'kms_key_id': snapshot.get('KmsKeyId', 'N/A'),
                        'is_compliant': encrypted,
                        'security_note': 'EBS snapshot encryption protects data at rest'
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
                    'message': 'No EBS snapshots found to check for encryption'
                }
            }
            findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in ec2_ebs_snapshots_encrypted check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'EBS Snapshot',
            'resource_id': f'error-check-{region}',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable encryption for all EBS snapshots'),
            'error': str(e)
        })
        
    return findings

def ec2_ebs_snapshots_encrypted(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=ec2_ebs_snapshots_encrypted_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = ec2_ebs_snapshots_encrypted(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

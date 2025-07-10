#!/usr/bin/env python3
"""
aws_audit_manager_control_tower_guardrails_aws - ec2_ebs_volume_snapshots_exists

Checks whether EBS volumes are attached to EC2 instances
"""

import sys
import os
import json
from typing import Dict, List, Any
from datetime import datetime, timezone

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
                    'recommendation': entry.get('Recommendation', 'Ensure EBS volumes have recent snapshots for backup and recovery purposes')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'aws_audit_manager_control_tower_guardrails_aws',
        'function_name': 'ec2_ebs_volume_snapshots_exists',
        'id': 'CT.EC2.PR.8',
        'name': 'EBS Volume Snapshot Management',
        'description': 'Checks whether EBS volumes are attached to EC2 instances',
        'api_function': 'client=boto3.client(\'ec2\')',
        'user_function': 'describe_volumes()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Ensure EBS volumes have recent snapshots for backup and recovery purposes'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('ec2_ebs_volume_snapshots_exists')

def get_volume_snapshots(ec2_client, volume_id: str, logger) -> List[Dict[str, Any]]:
    """
    Get snapshots for a specific EBS volume.
    
    Args:
        ec2_client: EC2 client
        volume_id: EBS volume ID
        logger: Logger instance
        
    Returns:
        List of snapshots for the volume
    """
    try:
        # Get snapshots for this volume
        snapshots_response = ec2_client.describe_snapshots(
            Filters=[
                {
                    'Name': 'volume-id',
                    'Values': [volume_id]
                }
            ],
            OwnerIds=['self']  # Only snapshots owned by the current account
        )
        
        snapshots = snapshots_response.get('Snapshots', [])
        
        # Sort snapshots by start time (most recent first)
        snapshots.sort(key=lambda x: x.get('StartTime', datetime.min.replace(tzinfo=timezone.utc)), reverse=True)
        
        return snapshots
        
    except Exception as e:
        logger.warning(f"Error getting snapshots for volume {volume_id}: {e}")
        return []

def analyze_snapshot_coverage(snapshots: List[Dict[str, Any]], logger) -> Dict[str, Any]:
    """
    Analyze snapshot coverage for compliance.
    
    Args:
        snapshots: List of snapshots
        logger: Logger instance
        
    Returns:
        Analysis results
    """
    analysis = {
        'has_snapshots': len(snapshots) > 0,
        'snapshot_count': len(snapshots),
        'most_recent_snapshot': None,
        'days_since_last_snapshot': None,
        'completed_snapshots': 0,
        'failed_snapshots': 0,
        'snapshot_details': []
    }
    
    if not snapshots:
        return analysis
    
    # Count snapshots by state
    for snapshot in snapshots:
        state = snapshot.get('State', 'unknown')
        if state == 'completed':
            analysis['completed_snapshots'] += 1
        elif state == 'error':
            analysis['failed_snapshots'] += 1
    
    # Get most recent completed snapshot
    completed_snapshots = [s for s in snapshots if s.get('State') == 'completed']
    
    if completed_snapshots:
        most_recent = completed_snapshots[0]
        analysis['most_recent_snapshot'] = {
            'snapshot_id': most_recent.get('SnapshotId'),
            'start_time': most_recent.get('StartTime', '').isoformat() if most_recent.get('StartTime') else None,
            'description': most_recent.get('Description', ''),
            'volume_size': most_recent.get('VolumeSize', 0),
            'encrypted': most_recent.get('Encrypted', False)
        }
        
        # Calculate days since last snapshot
        start_time = most_recent.get('StartTime')
        if start_time:
            now = datetime.now(timezone.utc)
            delta = now - start_time
            analysis['days_since_last_snapshot'] = delta.days
    
    # Add details for recent snapshots (last 5)
    for snapshot in snapshots[:5]:
        analysis['snapshot_details'].append({
            'snapshot_id': snapshot.get('SnapshotId'),
            'start_time': snapshot.get('StartTime', '').isoformat() if snapshot.get('StartTime') else None,
            'state': snapshot.get('State'),
            'progress': snapshot.get('Progress', ''),
            'description': snapshot.get('Description', ''),
            'volume_size': snapshot.get('VolumeSize', 0)
        })
    
    return analysis

def ec2_ebs_volume_snapshots_exists_check(ec2_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for ec2_ebs_volume_snapshots_exists.
    
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
        # Get all EBS volumes
        response = ec2_client.describe_volumes()
        volumes = response.get('Volumes', [])
        
        if not volumes:
            # No EBS volumes found
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'EBSVolume',
                'resource_id': f'no-ebs-volumes-{region}',
                'status': 'COMPLIANT',
                'compliance_status': 'PASS',
                'risk_level': 'LOW',
                'recommendation': 'No EBS volumes found in this region',
                'details': {
                    'volumes_count': 0,
                    'message': 'No EBS volumes found to check for snapshots'
                }
            }
            findings.append(finding)
            return findings
        
        # Check each volume for snapshots
        volumes_without_snapshots = 0
        volumes_with_old_snapshots = 0
        
        for volume in volumes:
            volume_id = volume.get('VolumeId', 'unknown')
            volume_state = volume.get('State', 'unknown')
            volume_size = volume.get('Size', 0)
            volume_type = volume.get('VolumeType', 'unknown')
            
            # Get snapshots for this volume
            snapshots = get_volume_snapshots(ec2_client, volume_id, logger)
            snapshot_analysis = analyze_snapshot_coverage(snapshots, logger)
            
            # Determine compliance status
            has_snapshots = snapshot_analysis['has_snapshots']
            days_since_last = snapshot_analysis['days_since_last_snapshot']
            
            # Compliance criteria:
            # 1. Volume should have at least one completed snapshot
            # 2. Most recent snapshot should be within 30 days (configurable)
            max_days_without_snapshot = 30
            
            if not has_snapshots:
                volumes_without_snapshots += 1
                status = 'NON_COMPLIANT'
                compliance_status = 'FAIL'
                risk_level = COMPLIANCE_DATA.get('risk_level', 'MEDIUM')
                recommendation = 'Create snapshots for EBS volume to ensure data backup and recovery capability'
            elif days_since_last is not None and days_since_last > max_days_without_snapshot:
                volumes_with_old_snapshots += 1
                status = 'NON_COMPLIANT'
                compliance_status = 'FAIL'
                risk_level = COMPLIANCE_DATA.get('risk_level', 'MEDIUM')
                recommendation = f'Most recent snapshot is {days_since_last} days old. Create more recent snapshots'
            else:
                status = 'COMPLIANT'
                compliance_status = 'PASS'
                risk_level = 'LOW'
                recommendation = 'EBS volume has appropriate snapshot coverage'
            
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'EBSVolume',
                'resource_id': volume_id,
                'status': status,
                'compliance_status': compliance_status,
                'risk_level': risk_level,
                'recommendation': recommendation,
                'details': {
                    'volume_id': volume_id,
                    'volume_state': volume_state,
                    'volume_size_gb': volume_size,
                    'volume_type': volume_type,
                    'has_snapshots': has_snapshots,
                    'total_snapshots': snapshot_analysis['snapshot_count'],
                    'completed_snapshots': snapshot_analysis['completed_snapshots'],
                    'failed_snapshots': snapshot_analysis['failed_snapshots'],
                    'days_since_last_snapshot': days_since_last,
                    'most_recent_snapshot': snapshot_analysis['most_recent_snapshot'],
                    'recent_snapshots': snapshot_analysis['snapshot_details'],
                    'availability_zone': volume.get('AvailabilityZone', 'unknown'),
                    'creation_time': volume.get('CreateTime', '').isoformat() if volume.get('CreateTime') else None,
                    'encrypted': volume.get('Encrypted', False),
                    'attachments': volume.get('Attachments', []),
                    'tags': volume.get('Tags', []),
                    'max_days_threshold': max_days_without_snapshot,
                    'security_note': 'Regular snapshots are essential for data protection and disaster recovery'
                }
            }
            
            findings.append(finding)
        
        logger.info(f"Checked {len(volumes)} EBS volumes: {volumes_without_snapshots} without snapshots, {volumes_with_old_snapshots} with old snapshots")
        
    except Exception as e:
        logger.error(f"Error in ec2_ebs_volume_snapshots_exists check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'EBSVolume',
            'resource_id': f'error-check-{region}',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Ensure EBS volumes have recent snapshots'),
            'error': str(e)
        })
        
    return findings

def ec2_ebs_volume_snapshots_exists(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=ec2_ebs_volume_snapshots_exists_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = ec2_ebs_volume_snapshots_exists(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

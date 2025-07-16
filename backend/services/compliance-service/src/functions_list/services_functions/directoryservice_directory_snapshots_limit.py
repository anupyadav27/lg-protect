#!/usr/bin/env python3
"""
kisa_isms_p_2023_korean_aws - directoryservice_directory_snapshots_limit

정보시스템의 가용성과 데이터 무결성을 유지하기 위하여 백업 대상, 주기, 방법, 보관장소, 보관기간, 소산 등의 절차를 수립·이행하여야 한다. 아울러 사고 발생 시 적시에 복구할 수 있도록 관리하여야 한다.
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
                    'recommendation': entry.get('Recommendation', 'Monitor and manage directory snapshots to ensure backup compliance and storage limits')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'iso27001_2022_aws',
        'function_name': 'directoryservice_directory_snapshots_limit',
        'id': 'ISO-27001-2022-A.12.3',
        'name': 'Information Backup',
        'description': 'Information backup should be carried out in accordance with an agreed backup policy.',
        'api_function': 'client = boto3.client(\'ds\')',
        'user_function': 'describe_snapshots()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Monitor and manage directory snapshots to ensure backup compliance and storage limits'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('directoryservice_directory_snapshots_limit')

def directoryservice_directory_snapshots_limit_check(ds_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for directoryservice_directory_snapshots_limit.
    
    Args:
        ds_client: Boto3 Directory Service client (auto-created by framework)
        region (str): AWS region (auto-managed by framework)
        profile (str): AWS profile name (auto-managed by framework)
        logger: Logger instance (auto-configured by framework)
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    # Define snapshot limits for compliance
    MAX_SNAPSHOTS_WARNING = 10  # Warning threshold
    MAX_SNAPSHOTS_CRITICAL = 20  # Critical threshold (AWS limit is typically higher)
    
    try:
        # Get all directories in the region
        response = ds_client.describe_directories()
        directories = response.get('DirectoryDescriptions', [])
        
        if not directories:
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'Directory Service',
                'resource_id': f'no-directories-{region}',
                'status': 'COMPLIANT',
                'compliance_status': 'PASS',
                'risk_level': 'LOW',
                'recommendation': 'No directories found in this region',
                'details': {
                    'directories_count': 0,
                    'message': 'No directories found to check for snapshot limits'
                }
            }
            findings.append(finding)
            return findings
        
        for directory in directories:
            directory_id = directory.get('DirectoryId', 'unknown')
            directory_name = directory.get('Name', 'unknown')
            directory_type = directory.get('Type', 'unknown')
            size = directory.get('Size', 'unknown')
            stage = directory.get('Stage', 'unknown')
            
            try:
                # Get snapshots for this directory
                snapshots_response = ds_client.describe_snapshots(DirectoryId=directory_id)
                snapshots = snapshots_response.get('Snapshots', [])
                snapshot_count = len(snapshots)
                
                # Determine compliance status based on snapshot count
                if snapshot_count >= MAX_SNAPSHOTS_CRITICAL:
                    status = 'NON_COMPLIANT'
                    compliance_status = 'FAIL'
                    risk_level = 'HIGH'
                    recommendation = f'Directory has {snapshot_count} snapshots, exceeding critical limit of {MAX_SNAPSHOTS_CRITICAL}. Consider cleaning up old snapshots'
                elif snapshot_count >= MAX_SNAPSHOTS_WARNING:
                    status = 'NON_COMPLIANT'
                    compliance_status = 'FAIL'
                    risk_level = 'MEDIUM'
                    recommendation = f'Directory has {snapshot_count} snapshots, exceeding warning limit of {MAX_SNAPSHOTS_WARNING}. Monitor and plan cleanup'
                else:
                    status = 'COMPLIANT'
                    compliance_status = 'PASS'
                    risk_level = 'LOW'
                    recommendation = f'Directory snapshot count ({snapshot_count}) is within acceptable limits'
                
                # Get snapshot details
                snapshot_details = []
                for snapshot in snapshots:
                    snapshot_details.append({
                        'snapshot_id': snapshot.get('SnapshotId', 'unknown'),
                        'name': snapshot.get('Name', 'unknown'),
                        'status': snapshot.get('Status', 'unknown'),
                        'start_time': str(snapshot.get('StartTime', 'unknown')),
                        'type': snapshot.get('Type', 'unknown')
                    })
                
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'Directory Service',
                    'resource_id': directory_id,
                    'status': status,
                    'compliance_status': compliance_status,
                    'risk_level': risk_level,
                    'recommendation': recommendation,
                    'details': {
                        'directory_id': directory_id,
                        'directory_name': directory_name,
                        'directory_type': directory_type,
                        'size': size,
                        'stage': stage,
                        'snapshot_count': snapshot_count,
                        'warning_limit': MAX_SNAPSHOTS_WARNING,
                        'critical_limit': MAX_SNAPSHOTS_CRITICAL,
                        'snapshots': snapshot_details,
                        'is_compliant': status == 'COMPLIANT',
                        'security_note': 'Excessive snapshots can lead to storage costs and management overhead'
                    }
                }
                
                findings.append(finding)
                
            except Exception as snapshot_error:
                logger.warning(f"Could not check snapshots for directory {directory_id}: {snapshot_error}")
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'Directory Service',
                    'resource_id': directory_id,
                    'status': 'ERROR',
                    'compliance_status': 'ERROR',
                    'risk_level': 'MEDIUM',
                    'recommendation': 'Unable to check directory snapshots',
                    'details': {
                        'directory_id': directory_id,
                        'directory_name': directory_name,
                        'error': str(snapshot_error),
                        'note': 'Could not retrieve snapshot information'
                    }
                }
                findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in directoryservice_directory_snapshots_limit check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'Directory Service',
            'resource_id': f'error-check-{region}',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Monitor and manage directory snapshots'),
            'error': str(e)
        })
        
    return findings

def directoryservice_directory_snapshots_limit(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=directoryservice_directory_snapshots_limit_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = directoryservice_directory_snapshots_limit(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

#!/usr/bin/env python3
"""
pci_4.0_aws - documentdb_cluster_public_snapshot

Ensure DocumentDB cluster snapshots are not publicly accessible to prevent unauthorized access to sensitive data.
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
                    'recommendation': entry.get('Recommendation', 'Ensure DocumentDB cluster snapshots are not publicly accessible')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'pci_4.0_aws',
        'function_name': 'documentdb_cluster_public_snapshot',
        'id': 'PCI-DSS-4.0-1.3',
        'name': 'DocumentDB Cluster Snapshot Public Access',
        'description': 'Ensure DocumentDB cluster snapshots are not publicly accessible to prevent unauthorized access to sensitive data.',
        'api_function': 'client=boto3.client(\'docdb\')',
        'user_function': 'describe_db_cluster_snapshots()',
        'risk_level': 'HIGH',
        'recommendation': 'Ensure DocumentDB cluster snapshots are not publicly accessible and restrict access to authorized users only'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('documentdb_cluster_public_snapshot')

def documentdb_cluster_public_snapshot_check(docdb_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for documentdb_cluster_public_snapshot.
    
    Args:
        docdb_client: Boto3 DocumentDB client (auto-created by framework)
        region (str): AWS region (auto-managed by framework)
        profile (str): AWS profile name (auto-managed by framework)
        logger: Logger instance (auto-configured by framework)
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    try:
        # Get all DocumentDB cluster snapshots
        response = docdb_client.describe_db_cluster_snapshots()
        snapshots = response.get('DBClusterSnapshots', [])
        
        if not snapshots:
            # No snapshots found - this is compliant
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'DocumentDB',
                'resource_id': f'no-snapshots-{region}',
                'status': 'COMPLIANT',
                'compliance_status': 'PASS',
                'risk_level': 'LOW',
                'recommendation': 'No DocumentDB cluster snapshots found in this region',
                'details': {
                    'snapshots_count': 0,
                    'message': 'No DocumentDB cluster snapshots found to check for public access'
                }
            }
            findings.append(finding)
            return findings
        
        for snapshot in snapshots:
            snapshot_id = snapshot.get('DBClusterSnapshotIdentifier', 'unknown')
            snapshot_arn = snapshot.get('DBClusterSnapshotArn', 'unknown')
            
            try:
                # Check snapshot attributes to determine if it's publicly accessible
                attributes_response = docdb_client.describe_db_cluster_snapshot_attributes(
                    DBClusterSnapshotIdentifier=snapshot_id
                )
                
                snapshot_attributes = attributes_response.get('DBClusterSnapshotAttributesResult', {})
                attributes = snapshot_attributes.get('DBClusterSnapshotAttributes', [])
                
                # Check for public access
                is_public = False
                restore_attribute = None
                
                for attribute in attributes:
                    if attribute.get('AttributeName') == 'restore':
                        restore_attribute = attribute
                        attribute_values = attribute.get('AttributeValues', [])
                        if 'all' in attribute_values:
                            is_public = True
                        break
                
                # Determine compliance status
                if is_public:
                    status = 'NON_COMPLIANT'
                    compliance_status = 'FAIL'
                    risk_level = COMPLIANCE_DATA.get('risk_level', 'HIGH')
                    recommendation = COMPLIANCE_DATA.get('recommendation', 'Make snapshot private')
                else:
                    status = 'COMPLIANT'
                    compliance_status = 'PASS'
                    risk_level = 'LOW'
                    recommendation = 'DocumentDB cluster snapshot is properly secured'
                
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'DocumentDB',
                    'resource_id': snapshot_id,
                    'status': status,
                    'compliance_status': compliance_status,
                    'risk_level': risk_level,
                    'recommendation': recommendation,
                    'details': {
                        'snapshot_id': snapshot_id,
                        'snapshot_arn': snapshot_arn,
                        'cluster_identifier': snapshot.get('DBClusterIdentifier', 'unknown'),
                        'engine': snapshot.get('Engine', 'unknown'),
                        'snapshot_type': snapshot.get('SnapshotType', 'unknown'),
                        'is_public': is_public,
                        'restore_attribute': restore_attribute,
                        'status': snapshot.get('Status', 'unknown'),
                        'creation_time': snapshot.get('SnapshotCreateTime', '').isoformat() if snapshot.get('SnapshotCreateTime') else 'unknown'
                    }
                }
                
                findings.append(finding)
                
            except Exception as snapshot_error:
                logger.warning(f"Error checking attributes for snapshot {snapshot_id}: {snapshot_error}")
                # Create finding for error case
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'DocumentDB',
                    'resource_id': snapshot_id,
                    'status': 'ERROR',
                    'compliance_status': 'ERROR',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                    'recommendation': 'Unable to check snapshot attributes - verify permissions',
                    'details': {
                        'snapshot_id': snapshot_id,
                        'error': str(snapshot_error)
                    }
                }
                findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in documentdb_cluster_public_snapshot check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'DocumentDB',
            'resource_id': f'error-check-{region}',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Ensure DocumentDB cluster snapshots are not publicly accessible'),
            'error': str(e)
        })
        
    return findings

def documentdb_cluster_public_snapshot(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=documentdb_cluster_public_snapshot_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = documentdb_cluster_public_snapshot(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

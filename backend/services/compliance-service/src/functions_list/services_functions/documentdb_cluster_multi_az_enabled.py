#!/usr/bin/env python3
"""
iso27001_2022_aws - documentdb_cluster_multi_az_enabled

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
                    'risk_level': entry.get('Risk Level', 'HIGH'),
                    'recommendation': entry.get('Recommendation', 'Enable Multi-AZ for DocumentDB clusters to ensure high availability')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'iso27001_2022_aws',
        'function_name': 'documentdb_cluster_multi_az_enabled',
        'id': 'ISO-27001-2022-A.17.1.2',
        'name': 'Implementing information security continuity',
        'description': 'Information processing facilities should be implemented with redundancy sufficient to meet availability',
        'api_function': 'client=boto3.client(\'docdb\')',
        'user_function': 'describe_db_clusters()',
        'risk_level': 'HIGH',
        'recommendation': 'Enable Multi-AZ for DocumentDB clusters to ensure high availability'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('documentdb_cluster_multi_az_enabled')

def documentdb_cluster_multi_az_enabled_check(docdb_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for documentdb_cluster_multi_az_enabled.
    
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
        # Get all DocumentDB clusters
        response = docdb_client.describe_db_clusters()
        clusters = response.get('DBClusters', [])
        
        if not clusters:
            # No DocumentDB clusters found
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'DocumentDB',
                'resource_id': f'no-clusters-{region}',
                'status': 'COMPLIANT',
                'compliance_status': 'PASS',
                'risk_level': 'LOW',
                'recommendation': 'No DocumentDB clusters found in this region',
                'details': {
                    'clusters_count': 0,
                    'message': 'No DocumentDB clusters found to check for Multi-AZ configuration'
                }
            }
            findings.append(finding)
            return findings
        
        # Check each cluster for Multi-AZ configuration
        for cluster in clusters:
            cluster_identifier = cluster.get('DBClusterIdentifier', 'unknown')
            cluster_arn = cluster.get('DBClusterArn', 'unknown')
            multi_az = cluster.get('MultiAZ', False)
            cluster_status = cluster.get('Status', 'unknown')
            availability_zones = cluster.get('AvailabilityZones', [])
            
            if multi_az:
                # Cluster has Multi-AZ enabled - compliant
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'DocumentDB',
                    'resource_id': cluster_identifier,
                    'status': 'COMPLIANT',
                    'compliance_status': 'PASS',
                    'risk_level': 'LOW',
                    'recommendation': 'DocumentDB cluster has Multi-AZ enabled for high availability',
                    'details': {
                        'cluster_identifier': cluster_identifier,
                        'cluster_arn': cluster_arn,
                        'multi_az': multi_az,
                        'cluster_status': cluster_status,
                        'availability_zones': availability_zones,
                        'availability_zones_count': len(availability_zones),
                        'engine': cluster.get('Engine', ''),
                        'engine_version': cluster.get('EngineVersion', ''),
                        'backup_retention_period': cluster.get('BackupRetentionPeriod', 0),
                        'preferred_backup_window': cluster.get('PreferredBackupWindow', ''),
                        'preferred_maintenance_window': cluster.get('PreferredMaintenanceWindow', '')
                    }
                }
            else:
                # Cluster does not have Multi-AZ enabled - non-compliant
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'DocumentDB',
                    'resource_id': cluster_identifier,
                    'status': 'NON_COMPLIANT',
                    'compliance_status': 'FAIL',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable Multi-AZ for this DocumentDB cluster'),
                    'details': {
                        'cluster_identifier': cluster_identifier,
                        'cluster_arn': cluster_arn,
                        'multi_az': multi_az,
                        'cluster_status': cluster_status,
                        'availability_zones': availability_zones,
                        'availability_zones_count': len(availability_zones),
                        'engine': cluster.get('Engine', ''),
                        'engine_version': cluster.get('EngineVersion', ''),
                        'backup_retention_period': cluster.get('BackupRetentionPeriod', 0),
                        'preferred_backup_window': cluster.get('PreferredBackupWindow', ''),
                        'preferred_maintenance_window': cluster.get('PreferredMaintenanceWindow', ''),
                        'issue': 'Multi-AZ is not enabled',
                        'remediation': 'Enable Multi-AZ deployment to ensure high availability and automatic failover capability'
                    }
                }
            
            findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in documentdb_cluster_multi_az_enabled check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'DocumentDB',
            'resource_id': f'error-check-{region}',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable Multi-AZ for DocumentDB clusters'),
            'error': str(e)
        })
        
    return findings

def documentdb_cluster_multi_az_enabled(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=documentdb_cluster_multi_az_enabled_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = documentdb_cluster_multi_az_enabled(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

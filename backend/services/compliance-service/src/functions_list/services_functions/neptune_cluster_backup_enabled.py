#!/usr/bin/env python3
"""
aws_foundational_security_best_practices_aws - neptune_cluster_backup_enabled

This control checks whether Neptune DB clusters have automated backups enabled and retention period configured.
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
                    'recommendation': entry.get('Recommendation', 'Enable automated backups for Neptune clusters')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'aws_foundational_security_best_practices_aws',
        'function_name': 'neptune_cluster_backup_enabled',
        'id': 'Neptune.1',
        'name': 'Neptune DB clusters should have automated backups enabled',
        'description': 'This control checks whether Neptune DB clusters have automated backups enabled and retention period configured.',
        'api_function': 'client = boto3.client("neptune")',
        'user_function': 'describe_db_clusters()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Enable automated backups for Neptune clusters'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('neptune_cluster_backup_enabled')

def neptune_cluster_backup_enabled_check(neptune_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for neptune_cluster_backup_enabled.
    
    Args:
        neptune_client: Boto3 Neptune client (auto-created by framework)
        region (str): AWS region (auto-managed by framework)
        profile (str): AWS profile name (auto-managed by framework)
        logger: Logger instance (auto-configured by framework)
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    try:
        logger.info("Checking Neptune clusters for backup configuration...")
        
        # Get all Neptune clusters
        response = neptune_client.describe_db_clusters()
        clusters = response.get('DBClusters', [])
        
        if not clusters:
            logger.info("No Neptune clusters found in this region")
            return findings
        
        for cluster in clusters:
            cluster_identifier = cluster.get('DBClusterIdentifier', 'Unknown')
            backup_retention_period = cluster.get('BackupRetentionPeriod', 0)
            preferred_backup_window = cluster.get('PreferredBackupWindow', 'Not configured')
            
            # Determine compliance status
            # Neptune clusters should have backup retention period > 0 (automatic backups enabled)
            if backup_retention_period > 0:
                status = 'COMPLIANT'
                compliance_status = 'PASS'
                message = f"Neptune cluster has automated backups enabled with {backup_retention_period} days retention"
            else:
                status = 'NON_COMPLIANT'
                compliance_status = 'FAIL'
                message = "Neptune cluster does not have automated backups enabled"
            
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'Neptune Cluster',
                'resource_id': cluster_identifier,
                'status': status,
                'compliance_status': compliance_status,
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable automated backups for Neptune clusters'),
                'details': {
                    'cluster_identifier': cluster_identifier,
                    'backup_retention_period': backup_retention_period,
                    'preferred_backup_window': preferred_backup_window,
                    'engine': cluster.get('Engine', 'Unknown'),
                    'engine_version': cluster.get('EngineVersion', 'Unknown'),
                    'status': cluster.get('Status', 'Unknown'),
                    'message': message
                }
            }
            
            findings.append(finding)
            
    except Exception as e:
        logger.error(f"Error in neptune_cluster_backup_enabled check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'Neptune Cluster',
            'resource_id': 'Unknown',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable automated backups for Neptune clusters'),
            'error': str(e),
            'details': {
                'error_message': str(e),
                'check_type': 'neptune_cluster_backup_enabled'
            }
        })
        
    return findings

def neptune_cluster_backup_enabled(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=neptune_cluster_backup_enabled_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = neptune_cluster_backup_enabled(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

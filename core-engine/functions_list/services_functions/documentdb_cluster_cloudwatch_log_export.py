#!/usr/bin/env python3
"""
iso27001_2022_aws - documentdb_cluster_cloudwatch_log_export

Logs that record activities, exceptions, faults and other relevant events should be produced, stored, protected and analysed.
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
                    'recommendation': entry.get('Recommendation', 'Enable CloudWatch log export for DocumentDB clusters')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'iso27001_2022_aws',
        'function_name': 'documentdb_cluster_cloudwatch_log_export',
        'id': 'ISO-27001-2022-A.12.4.1',
        'name': 'Event Logging',
        'description': 'Logs that record activities, exceptions, faults and other relevant events should be produced, stored, protected and analysed.',
        'api_function': 'client=boto3.client(\'docdb\')',
        'user_function': 'describe_db_clusters()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Enable CloudWatch log export for DocumentDB clusters to maintain audit trails'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('documentdb_cluster_cloudwatch_log_export')

def documentdb_cluster_cloudwatch_log_export_check(docdb_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for documentdb_cluster_cloudwatch_log_export.
    
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
            # No clusters found - this is compliant
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
                    'message': 'No DocumentDB clusters found to check for CloudWatch log export'
                }
            }
            findings.append(finding)
            return findings
        
        for cluster in clusters:
            cluster_id = cluster.get('DBClusterIdentifier', 'unknown')
            cluster_arn = cluster.get('DBClusterArn', 'unknown')
            
            # Check enabled log types
            enabled_cloudwatch_logs_exports = cluster.get('EnabledCloudwatchLogsExports', [])
            
            # DocumentDB supports audit logs
            expected_log_types = ['audit']
            missing_log_types = []
            
            for log_type in expected_log_types:
                if log_type not in enabled_cloudwatch_logs_exports:
                    missing_log_types.append(log_type)
            
            # Determine compliance status
            if missing_log_types:
                status = 'NON_COMPLIANT'
                compliance_status = 'FAIL'
                risk_level = COMPLIANCE_DATA.get('risk_level', 'MEDIUM')
                recommendation = f"Enable CloudWatch log export for missing log types: {', '.join(missing_log_types)}"
            else:
                status = 'COMPLIANT'
                compliance_status = 'PASS'
                risk_level = 'LOW'
                recommendation = 'CloudWatch log export is properly configured for DocumentDB cluster'
            
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'DocumentDB',
                'resource_id': cluster_id,
                'status': status,
                'compliance_status': compliance_status,
                'risk_level': risk_level,
                'recommendation': recommendation,
                'details': {
                    'cluster_id': cluster_id,
                    'cluster_arn': cluster_arn,
                    'engine': cluster.get('Engine', 'unknown'),
                    'engine_version': cluster.get('EngineVersion', 'unknown'),
                    'enabled_cloudwatch_logs_exports': enabled_cloudwatch_logs_exports,
                    'expected_log_types': expected_log_types,
                    'missing_log_types': missing_log_types,
                    'status': cluster.get('Status', 'unknown'),
                    'cluster_create_time': cluster.get('ClusterCreateTime', '').isoformat() if cluster.get('ClusterCreateTime') else 'unknown',
                    'backup_retention_period': cluster.get('BackupRetentionPeriod', 0),
                    'preferred_backup_window': cluster.get('PreferredBackupWindow', 'unknown'),
                    'preferred_maintenance_window': cluster.get('PreferredMaintenanceWindow', 'unknown'),
                    'multi_az': cluster.get('MultiAZ', False),
                    'storage_encrypted': cluster.get('StorageEncrypted', False)
                }
            }
            
            findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in documentdb_cluster_cloudwatch_log_export check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'DocumentDB',
            'resource_id': f'error-check-{region}',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable CloudWatch log export for DocumentDB clusters'),
            'error': str(e)
        })
        
    return findings

def documentdb_cluster_cloudwatch_log_export(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=documentdb_cluster_cloudwatch_log_export_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = documentdb_cluster_cloudwatch_log_export(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

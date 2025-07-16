#!/usr/bin/env python3
"""
aws_foundational_security_best_practices_aws - documentdb_cluster_storage_encrypted

This control checks whether an Amazon DocumentDB cluster is encrypted at rest. The control fails if an Amazon DocumentDB cluster isn't encrypted at rest.
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
                    'recommendation': entry.get('Recommendation', 'Enable encryption at rest for DocumentDB clusters')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'aws_foundational_security_best_practices_aws',
        'function_name': 'documentdb_cluster_storage_encrypted',
        'id': 'DocumentDB.1',
        'name': 'Amazon DocumentDB clusters should be encrypted at rest',
        'description': 'This control checks whether an Amazon DocumentDB cluster is encrypted at rest. The control fails if an Amazon DocumentDB cluster isn\'t encrypted at rest.',
        'api_function': 'client=boto3.client(\'docdb\')',
        'user_function': 'describe_db_clusters()',
        'risk_level': 'HIGH',
        'recommendation': 'Enable encryption at rest for DocumentDB clusters to protect sensitive data'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('documentdb_cluster_storage_encrypted')

def documentdb_cluster_storage_encrypted_check(docdb_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for documentdb_cluster_storage_encrypted.
    
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
        paginator = docdb_client.get_paginator('describe_db_clusters')
        
        for page in paginator.paginate():
            clusters = page.get('DBClusters', [])
            
            if not clusters:
                continue
                
            for cluster in clusters:
                cluster_identifier = cluster.get('DBClusterIdentifier', 'unknown')
                cluster_arn = cluster.get('DBClusterArn', 'unknown')
                engine = cluster.get('Engine', 'unknown')
                engine_version = cluster.get('EngineVersion', 'unknown')
                status = cluster.get('Status', 'unknown')
                storage_encrypted = cluster.get('StorageEncrypted', False)
                kms_key_id = cluster.get('KmsKeyId', None)
                
                # Determine compliance status
                if storage_encrypted:
                    status_result = 'COMPLIANT'
                    compliance_status = 'PASS'
                    risk_level = 'LOW'
                    recommendation = 'DocumentDB cluster storage is properly encrypted at rest'
                else:
                    status_result = 'NON_COMPLIANT'
                    compliance_status = 'FAIL'
                    risk_level = COMPLIANCE_DATA.get('risk_level', 'HIGH')
                    recommendation = COMPLIANCE_DATA.get('recommendation', 'Enable encryption at rest for this DocumentDB cluster')
                
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'DocumentDB Cluster',
                    'resource_id': cluster_identifier,
                    'status': status_result,
                    'compliance_status': compliance_status,
                    'risk_level': risk_level,
                    'recommendation': recommendation,
                    'details': {
                        'db_cluster_identifier': cluster_identifier,
                        'db_cluster_arn': cluster_arn,
                        'engine': engine,
                        'engine_version': engine_version,
                        'cluster_status': status,
                        'storage_encrypted': storage_encrypted,
                        'kms_key_id': kms_key_id or 'N/A',
                        'is_compliant': storage_encrypted,
                        'security_note': 'Encryption at rest protects data stored in DocumentDB clusters'
                    }
                }
                
                findings.append(finding)
        
        # If no clusters found, create an informational finding
        if not findings:
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'DocumentDB Cluster',
                'resource_id': f'no-clusters-{region}',
                'status': 'COMPLIANT',
                'compliance_status': 'PASS',
                'risk_level': 'LOW',
                'recommendation': 'No DocumentDB clusters found in this region',
                'details': {
                    'clusters_count': 0,
                    'message': 'No DocumentDB clusters found to check for encryption'
                }
            }
            findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in documentdb_cluster_storage_encrypted check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'DocumentDB Cluster',
            'resource_id': f'error-check-{region}',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable encryption at rest for DocumentDB clusters'),
            'error': str(e)
        })
        
    return findings

def documentdb_cluster_storage_encrypted(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=documentdb_cluster_storage_encrypted_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = documentdb_cluster_storage_encrypted(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

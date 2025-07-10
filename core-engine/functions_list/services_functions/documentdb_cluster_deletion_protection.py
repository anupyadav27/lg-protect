#!/usr/bin/env python3
"""
kisa_isms_p_2023_korean_aws - documentdb_cluster_deletion_protection

정보시스템의 가용성 보장을 위하여 성능 및 용량 요구사항을 정의하고 현황을 지속적으로 모니터링하여야 하며, 장애 발생 시 효과적으로 대응하기 위한 탐지·기록·분석·복구·보고 등의 절차를 수립·관리하여야 한다.
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
                    'recommendation': entry.get('Recommendation', 'Enable deletion protection for DocumentDB clusters')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'kisa_isms_p_2023_korean_aws',
        'function_name': 'documentdb_cluster_deletion_protection',
        'id': 'KISA-ISMS-P-2023-2.9.3',
        'name': '백업 및 복구관리',
        'description': '정보시스템의 가용성 보장을 위하여 성능 및 용량 요구사항을 정의하고 현황을 지속적으로 모니터링하여야 하며, 장애 발생 시 효과적으로 대응하기 위한 탐지·기록·분석·복구·보고 등의 절차를 수립·관리하여야 한다.',
        'api_function': 'client=boto3.client(\'docdb\')',
        'user_function': 'describe_db_clusters()',
        'risk_level': 'HIGH',
        'recommendation': 'Enable deletion protection for DocumentDB clusters'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('documentdb_cluster_deletion_protection')

def documentdb_cluster_deletion_protection_check(docdb_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for documentdb_cluster_deletion_protection.
    
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
                    'message': 'No DocumentDB clusters found to check for deletion protection'
                }
            }
            findings.append(finding)
            return findings
        
        # Check each cluster for deletion protection
        for cluster in clusters:
            cluster_identifier = cluster.get('DBClusterIdentifier', 'unknown')
            cluster_arn = cluster.get('DBClusterArn', 'unknown')
            deletion_protection = cluster.get('DeletionProtection', False)
            cluster_status = cluster.get('Status', 'unknown')
            
            if deletion_protection:
                # Cluster has deletion protection enabled - compliant
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'DocumentDB',
                    'resource_id': cluster_identifier,
                    'status': 'COMPLIANT',
                    'compliance_status': 'PASS',
                    'risk_level': 'LOW',
                    'recommendation': 'DocumentDB cluster has deletion protection enabled',
                    'details': {
                        'cluster_identifier': cluster_identifier,
                        'cluster_arn': cluster_arn,
                        'deletion_protection': deletion_protection,
                        'cluster_status': cluster_status,
                        'engine': cluster.get('Engine', ''),
                        'engine_version': cluster.get('EngineVersion', ''),
                        'master_username': cluster.get('MasterUsername', ''),
                        'multi_az': cluster.get('MultiAZ', False),
                        'backup_retention_period': cluster.get('BackupRetentionPeriod', 0)
                    }
                }
            else:
                # Cluster does not have deletion protection enabled - non-compliant
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'DocumentDB',
                    'resource_id': cluster_identifier,
                    'status': 'NON_COMPLIANT',
                    'compliance_status': 'FAIL',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable deletion protection for this DocumentDB cluster'),
                    'details': {
                        'cluster_identifier': cluster_identifier,
                        'cluster_arn': cluster_arn,
                        'deletion_protection': deletion_protection,
                        'cluster_status': cluster_status,
                        'engine': cluster.get('Engine', ''),
                        'engine_version': cluster.get('EngineVersion', ''),
                        'master_username': cluster.get('MasterUsername', ''),
                        'multi_az': cluster.get('MultiAZ', False),
                        'backup_retention_period': cluster.get('BackupRetentionPeriod', 0),
                        'issue': 'Deletion protection is not enabled',
                        'remediation': 'Enable deletion protection to prevent accidental cluster deletion'
                    }
                }
            
            findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in documentdb_cluster_deletion_protection check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'DocumentDB',
            'resource_id': f'error-check-{region}',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable deletion protection for DocumentDB clusters'),
            'error': str(e)
        })
        
    return findings

def documentdb_cluster_deletion_protection(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=documentdb_cluster_deletion_protection_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = documentdb_cluster_deletion_protection(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

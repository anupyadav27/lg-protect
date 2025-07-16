#!/usr/bin/env python3
"""
aws_compliance_framework - dynamodb_accelerator_cluster_multi_az

Ensure DynamoDB Accelerator (DAX) clusters are configured for multi-AZ deployment for high availability.
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
                    'recommendation': entry.get('Recommendation', 'Configure DAX clusters for multi-AZ deployment')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'aws_compliance_framework',
        'function_name': 'dynamodb_accelerator_cluster_multi_az',
        'id': 'DAX-MAZ-001',
        'name': 'DynamoDB Accelerator Multi-AZ',
        'description': 'Ensure DynamoDB Accelerator (DAX) clusters are configured for multi-AZ deployment for high availability.',
        'api_function': 'client = boto3.client(\'dax\')',
        'user_function': 'describe_clusters()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Configure DAX clusters for multi-AZ deployment across multiple availability zones'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('dynamodb_accelerator_cluster_multi_az')

def dynamodb_accelerator_cluster_multi_az_check(dax_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for DAX cluster multi-AZ configuration.
    
    Args:
        dax_client: Boto3 DAX client (auto-created by framework)
        region (str): AWS region (auto-managed by framework)
        profile (str): AWS profile name (auto-managed by framework)
        logger: Logger instance (auto-configured by framework)
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    try:
        # Get all DAX clusters in the region
        response = dax_client.describe_clusters()
        clusters = response.get('Clusters', [])
        
        if not clusters:
            # No clusters found - compliant by default
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'DAX',
                'resource_id': f'no-clusters-{region}',
                'status': 'COMPLIANT',
                'compliance_status': 'PASS',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                'recommendation': 'No DAX clusters found in this region',
                'details': {
                    'total_clusters': 0,
                    'multi_az_clusters': 0,
                    'single_az_clusters': 0
                }
            }
            findings.append(finding)
            return findings
        
        multi_az_clusters = []
        single_az_clusters = []
        
        # Check multi-AZ configuration for each cluster
        for cluster in clusters:
            cluster_name = cluster.get('ClusterName', 'unknown')
            cluster_arn = cluster.get('ClusterArn', '')
            status = cluster.get('Status', 'unknown')
            
            # Get availability zones from nodes
            nodes = cluster.get('Nodes', [])
            availability_zones = set()
            
            for node in nodes:
                az = node.get('AvailabilityZone')
                if az:
                    availability_zones.add(az)
            
            cluster_info = {
                'cluster_name': cluster_name,
                'cluster_arn': cluster_arn,
                'status': status,
                'node_count': len(nodes),
                'availability_zones': list(availability_zones),
                'az_count': len(availability_zones),
                'node_type': cluster.get('NodeType', 'unknown'),
                'subnet_group': cluster.get('SubnetGroup', 'unknown')
            }
            
            # Consider multi-AZ if cluster spans multiple availability zones
            if len(availability_zones) > 1:
                multi_az_clusters.append(cluster_info)
            else:
                cluster_info['issue'] = f'Cluster deployed in only {len(availability_zones)} availability zone'
                single_az_clusters.append(cluster_info)
        
        # Create findings for single-AZ clusters (non-compliant)
        for cluster_info in single_az_clusters:
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'DAX Cluster',
                'resource_id': cluster_info['cluster_name'],
                'status': 'NON_COMPLIANT',
                'compliance_status': 'FAIL',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                'recommendation': COMPLIANCE_DATA.get('recommendation', 'Configure DAX clusters for multi-AZ deployment'),
                'details': {
                    'cluster_name': cluster_info['cluster_name'],
                    'cluster_arn': cluster_info.get('cluster_arn'),
                    'status': cluster_info.get('status'),
                    'node_count': cluster_info.get('node_count'),
                    'availability_zones': cluster_info.get('availability_zones'),
                    'az_count': cluster_info.get('az_count'),
                    'issue': cluster_info.get('issue'),
                    'impact': 'Single point of failure - cluster not resilient to AZ outages'
                }
            }
            findings.append(finding)
        
        # Create findings for multi-AZ clusters (compliant)
        for cluster_info in multi_az_clusters:
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'DAX Cluster',
                'resource_id': cluster_info['cluster_name'],
                'status': 'COMPLIANT',
                'compliance_status': 'PASS',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                'recommendation': 'Multi-AZ deployment is properly configured',
                'details': {
                    'cluster_name': cluster_info['cluster_name'],
                    'cluster_arn': cluster_info.get('cluster_arn'),
                    'status': cluster_info.get('status'),
                    'node_count': cluster_info.get('node_count'),
                    'availability_zones': cluster_info.get('availability_zones'),
                    'az_count': cluster_info.get('az_count'),
                    'node_type': cluster_info.get('node_type')
                }
            }
            findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in dynamodb_accelerator_cluster_multi_az check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'DAX',
            'resource_id': f'check-error-{region}',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Configure DAX clusters for multi-AZ deployment'),
            'error': str(e)
        })
        
    return findings

def dynamodb_accelerator_cluster_multi_az(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=dynamodb_accelerator_cluster_multi_az_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = dynamodb_accelerator_cluster_multi_az(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

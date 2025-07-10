#!/usr/bin/env python3
"""
iso27001_2022_aws - kafka_cluster_in_transit_encryption_enabled

Rules for the effective use of cryptography, including cryptographic key management, should be defined and implemented.
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
                    'recommendation': entry.get('Recommendation', 'Enable in-transit encryption for Kafka clusters')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'iso27001_2022_aws',
        'function_name': 'kafka_cluster_in_transit_encryption_enabled',
        'id': 'A.10.1.1',
        'name': 'Cryptographic Controls',
        'description': 'Rules for the effective use of cryptography, including cryptographic key management, should be defined and implemented.',
        'api_function': 'client = boto3.client("kafka")',
        'user_function': 'list_clusters(), describe_cluster()',
        'risk_level': 'HIGH',
        'recommendation': 'Enable in-transit encryption for Kafka clusters'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('kafka_cluster_in_transit_encryption_enabled')

def kafka_cluster_in_transit_encryption_enabled_check(kafka_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for kafka_cluster_in_transit_encryption_enabled.
    
    Args:
        kafka_client: Boto3 Kafka client (auto-created by framework)
        region (str): AWS region (auto-managed by framework)
        profile (str): AWS profile name (auto-managed by framework)
        logger: Logger instance (auto-configured by framework)
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    try:
        logger.info("Checking Kafka clusters for in-transit encryption...")
        
        # Get all Kafka clusters
        response = kafka_client.list_clusters()
        cluster_info_list = response.get('ClusterInfoList', [])
        
        if not cluster_info_list:
            logger.info("No Kafka clusters found in this region")
            return findings
        
        for cluster_info in cluster_info_list:
            cluster_arn = cluster_info.get('ClusterArn', 'Unknown')
            cluster_name = cluster_info.get('ClusterName', 'Unknown')
            
            try:
                # Get detailed cluster information
                cluster_details = kafka_client.describe_cluster(ClusterArn=cluster_arn)
                cluster_info_detail = cluster_details.get('ClusterInfo', {})
                
                cluster_state = cluster_info_detail.get('State', 'Unknown')
                encryption_info = cluster_info_detail.get('EncryptionInfo', {})
                encryption_in_transit = encryption_info.get('EncryptionInTransit', {})
                
                # Check in-transit encryption settings
                client_broker = encryption_in_transit.get('ClientBroker', 'PLAINTEXT')
                in_cluster = encryption_in_transit.get('InCluster', False)
                
                # Determine compliance status
                if client_broker == 'TLS' and in_cluster:
                    status = 'COMPLIANT'
                    compliance_status = 'PASS'
                    message = "Kafka cluster has full in-transit encryption enabled (TLS for client-broker and in-cluster)"
                elif client_broker == 'TLS_PLAINTEXT' and in_cluster:
                    status = 'COMPLIANT'
                    compliance_status = 'PASS'
                    message = "Kafka cluster has in-transit encryption enabled with TLS_PLAINTEXT for client-broker and TLS for in-cluster"
                elif client_broker == 'TLS':
                    status = 'NON_COMPLIANT'
                    compliance_status = 'FAIL'
                    message = "Kafka cluster has TLS for client-broker but in-cluster encryption is disabled"
                elif client_broker == 'TLS_PLAINTEXT':
                    status = 'NON_COMPLIANT'
                    compliance_status = 'FAIL'
                    message = "Kafka cluster allows plaintext communication for client-broker connections"
                else:
                    status = 'NON_COMPLIANT'
                    compliance_status = 'FAIL'
                    message = f"Kafka cluster has insufficient in-transit encryption (client-broker: {client_broker}, in-cluster: {in_cluster})"
                
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'Kafka Cluster',
                    'resource_id': cluster_name,
                    'status': status,
                    'compliance_status': compliance_status,
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable in-transit encryption for Kafka clusters'),
                    'details': {
                        'cluster_name': cluster_name,
                        'cluster_arn': cluster_arn,
                        'cluster_state': cluster_state,
                        'client_broker_encryption': client_broker,
                        'in_cluster_encryption': in_cluster,
                        'kafka_version': cluster_info_detail.get('CurrentVersion', 'Unknown'),
                        'number_of_broker_nodes': cluster_info_detail.get('NumberOfBrokerNodes', 'Unknown'),
                        'creation_time': str(cluster_info_detail.get('CreationTime', 'Unknown')),
                        'message': message
                    }
                }
                
                findings.append(finding)
                
            except Exception as e:
                logger.error(f"Error describing cluster {cluster_name}: {e}")
                findings.append({
                    'region': region,
                    'profile': profile,
                    'resource_type': 'Kafka Cluster',
                    'resource_id': cluster_name,
                    'status': 'ERROR',
                    'compliance_status': 'ERROR',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable in-transit encryption for Kafka clusters'),
                    'error': str(e),
                    'details': {
                        'cluster_name': cluster_name,
                        'cluster_arn': cluster_arn,
                        'error_message': str(e)
                    }
                })
            
    except Exception as e:
        logger.error(f"Error in kafka_cluster_in_transit_encryption_enabled check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'Kafka Cluster',
            'resource_id': 'Unknown',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable in-transit encryption for Kafka clusters'),
            'error': str(e),
            'details': {
                'error_message': str(e),
                'check_type': 'kafka_cluster_in_transit_encryption_enabled'
            }
        })
        
    return findings

def kafka_cluster_in_transit_encryption_enabled(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=kafka_cluster_in_transit_encryption_enabled_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = kafka_cluster_in_transit_encryption_enabled(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

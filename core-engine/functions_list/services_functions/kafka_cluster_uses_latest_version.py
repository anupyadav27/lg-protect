#!/usr/bin/env python3
"""
kisa_isms_p_2023_korean_aws - kafka_cluster_uses_latest_version

데이터의 정확성 및 완전성을 보장하기 위하여 데이터 생성, 변경, 삭제 시 데이터의 무결성을 검증할 수 있는 절차를 수립하고 이행하여야 한다.
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
                    'recommendation': entry.get('Recommendation', 'Update Kafka clusters to the latest version')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'kisa_isms_p_2023_korean_aws',
        'function_name': 'kafka_cluster_uses_latest_version',
        'id': 'ISMS-P-DM-03',
        'name': 'Data Integrity Management',
        'description': '데이터의 정확성 및 완전성을 보장하기 위하여 데이터 생성, 변경, 삭제 시 데이터의 무결성을 검증할 수 있는 절차를 수립하고 이행하여야 한다.',
        'api_function': 'client = boto3.client("kafka")',
        'user_function': 'list_clusters(), describe_cluster()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Update Kafka clusters to the latest version'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('kafka_cluster_uses_latest_version')

def kafka_cluster_uses_latest_version_check(kafka_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for kafka_cluster_uses_latest_version.
    
    Args:
        kafka_client: Boto3 Kafka client (auto-created by framework)
        region (str): AWS region (auto-managed by framework)
        profile (str): AWS profile name (auto-managed by framework)
        logger: Logger instance (auto-configured by framework)
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    # Define latest stable Kafka versions (as of 2024)
    LATEST_KAFKA_VERSIONS = {
        '2.8.1': {'major': 2, 'minor': 8, 'patch': 1},
        '2.8.0': {'major': 2, 'minor': 8, 'patch': 0},
        '2.7.2': {'major': 2, 'minor': 7, 'patch': 2},
        '2.7.1': {'major': 2, 'minor': 7, 'patch': 1},
        '2.7.0': {'major': 2, 'minor': 7, 'patch': 0},
        '2.6.3': {'major': 2, 'minor': 6, 'patch': 3},
        '2.6.2': {'major': 2, 'minor': 6, 'patch': 2},
    }
    
    # Minimum acceptable versions (within 2 major versions)
    MIN_ACCEPTABLE_VERSION = {'major': 2, 'minor': 6, 'patch': 0}
    
    def parse_version(version_string):
        """Parse version string into major.minor.patch format."""
        try:
            parts = version_string.split('.')
            return {
                'major': int(parts[0]) if len(parts) > 0 else 0,
                'minor': int(parts[1]) if len(parts) > 1 else 0,
                'patch': int(parts[2]) if len(parts) > 2 else 0
            }
        except (ValueError, IndexError):
            return {'major': 0, 'minor': 0, 'patch': 0}
    
    def compare_versions(current, minimum):
        """Compare if current version meets minimum requirements."""
        if current['major'] > minimum['major']:
            return True
        elif current['major'] == minimum['major']:
            if current['minor'] > minimum['minor']:
                return True
            elif current['minor'] == minimum['minor']:
                return current['patch'] >= minimum['patch']
        return False
    
    try:
        logger.info("Checking Kafka clusters for latest version usage...")
        
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
                current_version = cluster_info_detail.get('CurrentVersion', 'Unknown')
                
                # Get Kafka version from broker node group
                broker_node_group = cluster_info_detail.get('BrokerNodeGroupInfo', {})
                instance_type = broker_node_group.get('InstanceType', 'Unknown')
                kafka_version = cluster_info_detail.get('CurrentBrokerSoftwareInfo', {}).get('KafkaVersion', 'Unknown')
                
                if kafka_version == 'Unknown':
                    status = 'NON_COMPLIANT'
                    compliance_status = 'FAIL'
                    message = "Unable to determine Kafka version"
                else:
                    # Parse and compare versions
                    current_parsed = parse_version(kafka_version)
                    is_acceptable = compare_versions(current_parsed, MIN_ACCEPTABLE_VERSION)
                    
                    # Check if it's one of the latest versions
                    is_latest = kafka_version in LATEST_KAFKA_VERSIONS
                    
                    if is_latest:
                        status = 'COMPLIANT'
                        compliance_status = 'PASS'
                        message = f"Kafka cluster is using a latest version: {kafka_version}"
                    elif is_acceptable:
                        status = 'COMPLIANT'
                        compliance_status = 'PASS'
                        message = f"Kafka cluster is using an acceptable version: {kafka_version}"
                    else:
                        status = 'NON_COMPLIANT'
                        compliance_status = 'FAIL'
                        message = f"Kafka cluster is using an outdated version: {kafka_version}. Consider upgrading to a newer version."
                
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'Kafka Cluster',
                    'resource_id': cluster_name,
                    'status': status,
                    'compliance_status': compliance_status,
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Update Kafka clusters to the latest version'),
                    'details': {
                        'cluster_name': cluster_name,
                        'cluster_arn': cluster_arn,
                        'cluster_state': cluster_state,
                        'current_version': current_version,
                        'kafka_version': kafka_version,
                        'instance_type': instance_type,
                        'number_of_broker_nodes': cluster_info_detail.get('NumberOfBrokerNodes', 'Unknown'),
                        'creation_time': str(cluster_info_detail.get('CreationTime', 'Unknown')),
                        'is_latest_version': kafka_version in LATEST_KAFKA_VERSIONS,
                        'minimum_acceptable_version': f"{MIN_ACCEPTABLE_VERSION['major']}.{MIN_ACCEPTABLE_VERSION['minor']}.{MIN_ACCEPTABLE_VERSION['patch']}",
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
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Update Kafka clusters to the latest version'),
                    'error': str(e),
                    'details': {
                        'cluster_name': cluster_name,
                        'cluster_arn': cluster_arn,
                        'error_message': str(e)
                    }
                })
            
    except Exception as e:
        logger.error(f"Error in kafka_cluster_uses_latest_version check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'Kafka Cluster',
            'resource_id': 'Unknown',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Update Kafka clusters to the latest version'),
            'error': str(e),
            'details': {
                'error_message': str(e),
                'check_type': 'kafka_cluster_uses_latest_version'
            }
        })
        
    return findings

def kafka_cluster_uses_latest_version(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=kafka_cluster_uses_latest_version_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = kafka_cluster_uses_latest_version(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

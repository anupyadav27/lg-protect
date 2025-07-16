#!/usr/bin/env python3
"""
fedramp_moderate_revision_4_aws - opensearch_service_domains_encryption_at_rest_enabled

The information system protects the confidentiality AND integrity of [Assignment: organization-defined information at rest].
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
                    'recommendation': entry.get('Recommendation', 'Review and remediate as needed')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'fedramp_moderate_revision_4_aws',
        'function_name': 'opensearch_service_domains_encryption_at_rest_enabled',
        'id': 'SC-28',
        'name': 'OpenSearch domains should have encryption at rest enabled',
        'description': 'The information system protects the confidentiality AND integrity of organization-defined information at rest',
        'api_function': 'client = boto3.client("opensearch")',
        'user_function': 'list_domain_names(), describe_domain_config()',
        'risk_level': 'HIGH',
        'recommendation': 'Enable encryption at rest for OpenSearch domains to protect data confidentiality'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('opensearch_service_domains_encryption_at_rest_enabled')

def opensearch_service_domains_encryption_at_rest_enabled_check(opensearch_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for opensearch_service_domains_encryption_at_rest_enabled.
    
    Args:
        opensearch_client: Boto3 OpenSearch client (auto-created by framework)
        region (str): AWS region (auto-managed by framework)
        profile (str): AWS profile name (auto-managed by framework)
        logger: Logger instance (auto-configured by framework)
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    try:
        logger.info(f"Checking OpenSearch domains encryption at rest in region {region}")
        
        # Get all OpenSearch domains
        domains_response = opensearch_client.list_domain_names()
        domain_names = domains_response.get('DomainNames', [])
        
        if not domain_names:
            logger.info(f"No OpenSearch domains found in region {region}")
            return findings
        
        # Check each domain for encryption at rest
        for domain_info in domain_names:
            domain_name = domain_info.get('DomainName', 'unknown')
            engine_type = domain_info.get('EngineType', 'OpenSearch')
            
            try:
                # Get domain configuration details
                config_response = opensearch_client.describe_domain_config(DomainName=domain_name)
                domain_config = config_response.get('DomainConfig', {})
                
                # Get encryption at rest configuration
                encryption_config = domain_config.get('EncryptionAtRestOptions', {})
                encryption_status = encryption_config.get('Status', {})
                encryption_enabled = encryption_status.get('Enabled', False)
                
                # Get KMS key information if encryption is enabled
                kms_key_id = encryption_status.get('KmsKeyId', '') if encryption_enabled else ''
                
                # Get additional domain information
                domain_endpoint_options = domain_config.get('DomainEndpointOptions', {}).get('Status', {})
                node_to_node_encryption = domain_config.get('NodeToNodeEncryptionOptions', {}).get('Status', {}).get('Enabled', False)
                
                # Get cluster configuration
                cluster_config = domain_config.get('ClusterConfig', {}).get('Status', {})
                instance_type = cluster_config.get('InstanceType', 'unknown')
                instance_count = cluster_config.get('InstanceCount', 0)
                dedicated_master_enabled = cluster_config.get('DedicatedMasterEnabled', False)
                
                # Get engine version
                engine_version = domain_config.get('EngineVersion', {}).get('Status', {}).get('Options', 'unknown')
                
                # Get access policies
                access_policies = domain_config.get('AccessPolicies', {}).get('Status', {}).get('Options', '')
                
                if encryption_enabled:
                    # Compliant: Encryption at rest is enabled
                    finding = {
                        'region': region,
                        'profile': profile,
                        'resource_type': 'OpenSearch Domain',
                        'resource_id': domain_name,
                        'status': 'COMPLIANT',
                        'compliance_status': 'PASS',
                        'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                        'recommendation': COMPLIANCE_DATA.get('recommendation', 'Encryption at rest is properly enabled'),
                        'details': {
                            'domain_name': domain_name,
                            'engine_type': engine_type,
                            'engine_version': engine_version,
                            'encryption_at_rest_enabled': encryption_enabled,
                            'kms_key_id': kms_key_id,
                            'node_to_node_encryption_enabled': node_to_node_encryption,
                            'cluster_config': {
                                'instance_type': instance_type,
                                'instance_count': instance_count,
                                'dedicated_master_enabled': dedicated_master_enabled
                            },
                            'domain_endpoint_options': domain_endpoint_options,
                            'has_access_policies': bool(access_policies.strip()) if access_policies else False
                        }
                    }
                else:
                    # Non-compliant: Encryption at rest is not enabled
                    finding = {
                        'region': region,
                        'profile': profile,
                        'resource_type': 'OpenSearch Domain',
                        'resource_id': domain_name,
                        'status': 'NON_COMPLIANT',
                        'compliance_status': 'FAIL',
                        'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                        'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable encryption at rest for this domain'),
                        'details': {
                            'domain_name': domain_name,
                            'engine_type': engine_type,
                            'engine_version': engine_version,
                            'encryption_at_rest_enabled': encryption_enabled,
                            'issue': 'Encryption at rest is not enabled for this OpenSearch domain',
                            'node_to_node_encryption_enabled': node_to_node_encryption,
                            'cluster_config': {
                                'instance_type': instance_type,
                                'instance_count': instance_count,
                                'dedicated_master_enabled': dedicated_master_enabled
                            },
                            'security_risk': 'Data stored in the domain is not encrypted, potentially exposing sensitive information',
                            'remediation_steps': [
                                'Note: Encryption at rest cannot be enabled on existing domains',
                                'Create a new domain with encryption at rest enabled',
                                'Migrate data from the unencrypted domain to the new encrypted domain',
                                'Update applications to use the new encrypted domain endpoint',
                                'Delete the old unencrypted domain after migration verification',
                                'Consider enabling node-to-node encryption as well'
                            ],
                            'domain_endpoint_options': domain_endpoint_options,
                            'has_access_policies': bool(access_policies.strip()) if access_policies else False
                        }
                    }
                
                findings.append(finding)
                
            except Exception as e:
                logger.error(f"Error checking OpenSearch domain {domain_name} in {region}: {e}")
                findings.append({
                    'region': region,
                    'profile': profile,
                    'resource_type': 'OpenSearch Domain',
                    'resource_id': domain_name,
                    'status': 'ERROR',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Review domain configuration'),
                    'error': str(e)
                })
        
    except Exception as e:
        logger.error(f"Error in opensearch_service_domains_encryption_at_rest_enabled check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'OpenSearch Domain',
            'status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Review and remediate as needed'),
            'error': str(e)
        })
        
    return findings

def opensearch_service_domains_encryption_at_rest_enabled(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=opensearch_service_domains_encryption_at_rest_enabled_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = opensearch_service_domains_encryption_at_rest_enabled(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

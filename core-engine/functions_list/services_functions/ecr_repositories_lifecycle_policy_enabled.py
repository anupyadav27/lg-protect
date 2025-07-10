#!/usr/bin/env python3
"""
pci_4.0_aws - ecr_repositories_lifecycle_policy_enabled

Checks if a private Amazon Elastic Container Registry (ECR) repository has at least one lifecycle policy configured
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
                    'recommendation': entry.get('Recommendation', 'Configure lifecycle policies for ECR repositories to manage image retention')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'pci_4.0_aws',
        'function_name': 'ecr_repositories_lifecycle_policy_enabled',
        'id': 'PCI-4.0-ECR-1',
        'name': 'ECR Lifecycle Policy',
        'description': 'Checks if a private Amazon Elastic Container Registry (ECR) repository has at least one lifecycle policy configured',
        'api_function': 'client = boto3.client(\'ecr\')',
        'user_function': 'list_repositories(), get_lifecycle_policy()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Configure lifecycle policies for ECR repositories to manage image retention'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('ecr_repositories_lifecycle_policy_enabled')

def ecr_repositories_lifecycle_policy_enabled_check(ecr_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for ecr_repositories_lifecycle_policy_enabled.
    
    Args:
        ecr_client: Boto3 ECR client (auto-created by framework)
        region (str): AWS region (auto-managed by framework)
        profile (str): AWS profile name (auto-managed by framework)
        logger: Logger instance (auto-configured by framework)
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    try:
        # Get all ECR repositories
        response = ecr_client.list_repositories()
        repositories = response.get('repositories', [])
        
        if not repositories:
            # No repositories found - this is compliant
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'ECR',
                'resource_id': f'no-repositories-{region}',
                'status': 'COMPLIANT',
                'compliance_status': 'PASS',
                'risk_level': 'LOW',
                'recommendation': 'No ECR repositories found in this region',
                'details': {
                    'repositories_count': 0,
                    'message': 'No ECR repositories to check for lifecycle policies'
                }
            }
            findings.append(finding)
            return findings
        
        # Check each repository for lifecycle policy
        for repo in repositories:
            repo_name = repo.get('repositoryName', 'unknown')
            repo_arn = repo.get('repositoryArn', 'unknown')
            
            try:
                # Try to get lifecycle policy for this repository
                lifecycle_response = ecr_client.get_lifecycle_policy(repositoryName=repo_name)
                
                # If we get here, the repository has a lifecycle policy
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'ECR',
                    'resource_id': repo_name,
                    'status': 'COMPLIANT',
                    'compliance_status': 'PASS',
                    'risk_level': 'LOW',
                    'recommendation': 'Repository has lifecycle policy configured',
                    'details': {
                        'repository_name': repo_name,
                        'repository_arn': repo_arn,
                        'registry_id': lifecycle_response.get('registryId', ''),
                        'policy_text_exists': bool(lifecycle_response.get('lifecyclePolicyText')),
                        'last_evaluated': lifecycle_response.get('lastEvaluatedAt'),
                        'has_lifecycle_policy': True
                    }
                }
                
            except ecr_client.exceptions.LifecyclePolicyNotFoundException:
                # Repository does not have a lifecycle policy
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'ECR',
                    'resource_id': repo_name,
                    'status': 'NON_COMPLIANT',
                    'compliance_status': 'FAIL',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Configure lifecycle policy for this ECR repository'),
                    'details': {
                        'repository_name': repo_name,
                        'repository_arn': repo_arn,
                        'registry_id': repo.get('registryId', ''),
                        'created_at': repo.get('createdAt'),
                        'has_lifecycle_policy': False,
                        'issue': 'No lifecycle policy configured'
                    }
                }
                
            except Exception as repo_error:
                # Error checking this specific repository
                logger.warning(f"Error checking lifecycle policy for repository {repo_name}: {repo_error}")
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'ECR',
                    'resource_id': repo_name,
                    'status': 'ERROR',
                    'compliance_status': 'ERROR',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                    'recommendation': 'Unable to check lifecycle policy for this repository',
                    'details': {
                        'repository_name': repo_name,
                        'repository_arn': repo_arn,
                        'error': str(repo_error)
                    }
                }
            
            findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in ecr_repositories_lifecycle_policy_enabled check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'ECR',
            'resource_id': f'error-check-{region}',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Configure lifecycle policies for ECR repositories'),
            'error': str(e)
        })
        
    return findings

def ecr_repositories_lifecycle_policy_enabled(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=ecr_repositories_lifecycle_policy_enabled_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = ecr_repositories_lifecycle_policy_enabled(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

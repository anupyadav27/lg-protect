#!/usr/bin/env python3
"""
iso27001_2022_aws - ecr_repositories_tag_immutability

Security mechanisms, service levels and service requirements of network services should be identified, implemented and monitored.
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
    """Load compliance metadata from compliance_checks.json."""
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
                    'recommendation': entry.get('Recommendation', 'Enable tag immutability for ECR repositories to prevent overwriting of existing tags')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'iso27001_2022_aws',
        'function_name': 'ecr_repositories_tag_immutability',
        'id': 'ECR.2',
        'name': 'ECR private repositories should have tag immutability configured',
        'description': 'Security mechanisms, service levels and service requirements of network services should be identified, implemented and monitored.',
        'api_function': 'client = boto3.client(\'ecr\')',
        'user_function': 'describe_repositories()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Enable tag immutability for ECR repositories to prevent overwriting of existing tags'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('ecr_repositories_tag_immutability')

def ecr_repositories_tag_immutability_check(ecr_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for ecr_repositories_tag_immutability.
    
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
        paginator = ecr_client.get_paginator('describe_repositories')
        
        for page in paginator.paginate():
            repositories = page.get('repositories', [])
            
            for repository in repositories:
                repository_name = repository['repositoryName']
                repository_arn = repository['repositoryArn']
                
                try:
                    # Check image tag mutability
                    image_tag_mutability = repository.get('imageTagMutability', 'MUTABLE')
                    
                    if image_tag_mutability == 'IMMUTABLE':
                        findings.append({
                            'region': region,
                            'profile': profile,
                            'resource_type': 'ECR Repository',
                            'resource_id': repository_name,
                            'status': 'COMPLIANT',
                            'compliance_status': 'PASS',
                            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable tag immutability for ECR repositories'),
                            'details': {
                                'repository_name': repository_name,
                                'repository_arn': repository_arn,
                                'image_tag_mutability': image_tag_mutability,
                                'registry_id': repository.get('registryId'),
                                'created_at': str(repository.get('createdAt'))
                            }
                        })
                    else:
                        findings.append({
                            'region': region,
                            'profile': profile,
                            'resource_type': 'ECR Repository',
                            'resource_id': repository_name,
                            'status': 'NON_COMPLIANT',
                            'compliance_status': 'FAIL',
                            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable tag immutability for ECR repositories'),
                            'details': {
                                'repository_name': repository_name,
                                'repository_arn': repository_arn,
                                'image_tag_mutability': image_tag_mutability,
                                'registry_id': repository.get('registryId'),
                                'created_at': str(repository.get('createdAt')),
                                'issue': 'Tag immutability is not enabled - tags can be overwritten'
                            }
                        })
                        
                except Exception as repo_error:
                    logger.error(f"Error checking repository {repository_name}: {repo_error}")
                    findings.append({
                        'region': region,
                        'profile': profile,
                        'resource_type': 'ECR Repository',
                        'resource_id': repository_name,
                        'status': 'ERROR',
                        'compliance_status': 'ERROR',
                        'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                        'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable tag immutability for ECR repositories'),
                        'error': str(repo_error)
                    })
                    
    except Exception as e:
        logger.error(f"Error in ecr_repositories_tag_immutability check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'ECR Repository',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable tag immutability for ECR repositories'),
            'error': str(e)
        })
        
    return findings

def ecr_repositories_tag_immutability(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=ecr_repositories_tag_immutability_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = ecr_repositories_tag_immutability(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

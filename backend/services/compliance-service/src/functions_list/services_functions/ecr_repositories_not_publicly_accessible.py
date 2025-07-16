#!/usr/bin/env python3
"""
iso27001_2022_aws - ecr_repositories_not_publicly_accessible

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
                    'risk_level': entry.get('Risk Level', 'HIGH'),
                    'recommendation': entry.get('Recommendation', 'Ensure ECR repositories are not publicly accessible')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'iso27001_2022_aws',
        'function_name': 'ecr_repositories_not_publicly_accessible',
        'id': 'ECR.4',
        'name': 'ECR repositories should not be publicly accessible',
        'description': 'Security mechanisms, service levels and service requirements of network services should be identified, implemented and monitored.',
        'api_function': 'client = boto3.client(\'ecr\')',
        'user_function': 'describe_repositories(), get_repository_policy()',
        'risk_level': 'HIGH',
        'recommendation': 'Ensure ECR repositories are not publicly accessible'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('ecr_repositories_not_publicly_accessible')

def ecr_repositories_not_publicly_accessible_check(ecr_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for ecr_repositories_not_publicly_accessible.
    
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
                registry_id = repository.get('registryId')
                
                try:
                    # Check repository policy for public access
                    try:
                        policy_response = ecr_client.get_repository_policy(
                            registryId=registry_id,
                            repositoryName=repository_name
                        )
                        
                        policy_text = policy_response.get('policyText', '{}')
                        policy = json.loads(policy_text)
                        
                        is_publicly_accessible = False
                        public_statements = []
                        
                        statements = policy.get('Statement', [])
                        if isinstance(statements, dict):
                            statements = [statements]
                        
                        for statement in statements:
                            effect = statement.get('Effect', '').upper()
                            principal = statement.get('Principal', {})
                            
                            # Check for public access patterns
                            if effect == 'ALLOW':
                                # Check for wildcard principals
                                if principal == '*' or principal == {'AWS': '*'}:
                                    is_publicly_accessible = True
                                    public_statements.append(statement)
                                elif isinstance(principal, dict):
                                    # Check for specific public access patterns
                                    aws_principals = principal.get('AWS', [])
                                    if isinstance(aws_principals, str):
                                        aws_principals = [aws_principals]
                                    
                                    for aws_principal in aws_principals:
                                        if aws_principal == '*' or aws_principal == 'arn:aws:iam::*:root':
                                            is_publicly_accessible = True
                                            public_statements.append(statement)
                                            break
                        
                        if is_publicly_accessible:
                            findings.append({
                                'region': region,
                                'profile': profile,
                                'resource_type': 'ECR Repository',
                                'resource_id': repository_name,
                                'status': 'NON_COMPLIANT',
                                'compliance_status': 'FAIL',
                                'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                                'recommendation': COMPLIANCE_DATA.get('recommendation', 'Remove public access from ECR repository policy'),
                                'details': {
                                    'repository_name': repository_name,
                                    'repository_arn': repository_arn,
                                    'registry_id': registry_id,
                                    'public_statements': public_statements,
                                    'issue': 'Repository has policy statements allowing public access'
                                }
                            })
                        else:
                            findings.append({
                                'region': region,
                                'profile': profile,
                                'resource_type': 'ECR Repository',
                                'resource_id': repository_name,
                                'status': 'COMPLIANT',
                                'compliance_status': 'PASS',
                                'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                                'recommendation': COMPLIANCE_DATA.get('recommendation', 'Continue monitoring repository access'),
                                'details': {
                                    'repository_name': repository_name,
                                    'repository_arn': repository_arn,
                                    'registry_id': registry_id,
                                    'has_policy': True,
                                    'public_access': False
                                }
                            })
                            
                    except ecr_client.exceptions.RepositoryPolicyNotFoundException:
                        # No policy means no public access - this is compliant
                        findings.append({
                            'region': region,
                            'profile': profile,
                            'resource_type': 'ECR Repository',
                            'resource_id': repository_name,
                            'status': 'COMPLIANT',
                            'compliance_status': 'PASS',
                            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Continue monitoring repository access'),
                            'details': {
                                'repository_name': repository_name,
                                'repository_arn': repository_arn,
                                'registry_id': registry_id,
                                'has_policy': False,
                                'public_access': False
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
                        'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                        'recommendation': COMPLIANCE_DATA.get('recommendation', 'Resolve errors and verify repository access'),
                        'error': str(repo_error)
                    })
                    
    except Exception as e:
        logger.error(f"Error in ecr_repositories_not_publicly_accessible check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'ECR Repository',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Resolve errors and verify repository access'),
            'error': str(e)
        })
        
    return findings

def ecr_repositories_not_publicly_accessible(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=ecr_repositories_not_publicly_accessible_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = ecr_repositories_not_publicly_accessible(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

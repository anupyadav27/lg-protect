#!/usr/bin/env python3
"""
kisa_isms_p_2023_aws - codeartifact_packages_external_public_publishing_disabled

Source programs must be managed so that only authorized users can access them, and it is a principle that they should not be stored in the operational environment.
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
        'compliance_name': 'kisa_isms_p_2023_aws',
        'function_name': 'codeartifact_packages_external_public_publishing_disabled',
        'id': '2.8.5',
        'name': 'Source Program Management',
        'description': 'Source programs must be managed so that only authorized users can access them, and it is a principle that they should not be stored in the operational environment.',
        'api_function': 'client = boto3.client(\'codeartifact\')',
        'user_function': 'list_domains(), list_repositories_in_domain(domain=...), get_repository_permissions_policy(domain=..., repository=...)',
        'risk_level': 'MEDIUM',
        'recommendation': 'Disable external public publishing on CodeArtifact repositories to prevent unauthorized access'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('codeartifact_packages_external_public_publishing_disabled')

def codeartifact_packages_external_public_publishing_disabled_check(codeartifact_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for codeartifact_packages_external_public_publishing_disabled.
    
    Args:
        codeartifact_client: Boto3 CodeArtifact client (auto-created by framework)
        region (str): AWS region (auto-managed by framework)
        profile (str): AWS profile name (auto-managed by framework)
        logger: Logger instance (auto-configured by framework)
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    try:
        # Get all CodeArtifact domains
        domains_response = codeartifact_client.list_domains()
        domains = domains_response.get('domains', [])
        
        if not domains:
            # No domains found - compliant by default
            findings.append({
                'region': region,
                'profile': profile,
                'resource_type': 'CodeArtifact',
                'resource_id': f'no-domains-{region}',
                'status': 'COMPLIANT',
                'compliance_status': 'PASS',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                'recommendation': 'No CodeArtifact domains found',
                'details': {
                    'domain_count': 0,
                    'message': 'No CodeArtifact domains exist in this region'
                }
            })
            return findings
        
        for domain in domains:
            domain_name = domain.get('name')
            domain_owner = domain.get('owner')
            
            try:
                # List repositories in the domain
                repos_response = codeartifact_client.list_repositories_in_domain(
                    domain=domain_name,
                    domainOwner=domain_owner
                )
                repositories = repos_response.get('repositories', [])
                
                for repo in repositories:
                    repo_name = repo.get('name')
                    
                    try:
                        # Get repository permissions policy
                        policy_response = codeartifact_client.get_repository_permissions_policy(
                            domain=domain_name,
                            domainOwner=domain_owner,
                            repository=repo_name
                        )
                        
                        policy_document = policy_response.get('policy', {})
                        
                        # Parse the policy to check for external public publishing permissions
                        external_public_publishing_enabled = False
                        policy_details = {}
                        
                        if isinstance(policy_document, str):
                            try:
                                policy_doc = json.loads(policy_document)
                                policy_details = policy_doc
                                
                                # Check for statements that allow external publishing
                                statements = policy_doc.get('Statement', [])
                                for statement in statements:
                                    if isinstance(statement, dict):
                                        effect = statement.get('Effect', '')
                                        actions = statement.get('Action', [])
                                        principals = statement.get('Principal', {})
                                        
                                        # Check for actions that allow publishing
                                        if effect == 'Allow':
                                            if isinstance(actions, str):
                                                actions = [actions]
                                            
                                            publish_actions = [
                                                'codeartifact:PublishPackageVersion',
                                                'codeartifact:PutPackageMetadata',
                                                'codeartifact:*'
                                            ]
                                            
                                            for action in actions:
                                                if any(pub_action in action for pub_action in publish_actions):
                                                    # Check if principals include external accounts
                                                    if isinstance(principals, dict):
                                                        if '*' in str(principals) or 'AWS' in principals:
                                                            aws_principals = principals.get('AWS', [])
                                                            if isinstance(aws_principals, str):
                                                                aws_principals = [aws_principals]
                                                            
                                                            for principal in aws_principals:
                                                                if principal == '*' or 'arn:aws:iam::' not in principal:
                                                                    external_public_publishing_enabled = True
                                                                    break
                                            
                                            if external_public_publishing_enabled:
                                                break
                                    
                                    if external_public_publishing_enabled:
                                        break
                                        
                            except json.JSONDecodeError:
                                logger.warning(f"Could not parse policy document for repository {repo_name}")
                        
                        # Create finding based on policy analysis
                        if external_public_publishing_enabled:
                            status = 'NON_COMPLIANT'
                            compliance_status = 'FAIL'
                            recommendation = COMPLIANCE_DATA.get('recommendation', 'Disable external public publishing on CodeArtifact repositories')
                        else:
                            status = 'COMPLIANT'
                            compliance_status = 'PASS'
                            recommendation = 'Repository properly restricts external publishing'
                        
                        finding = {
                            'region': region,
                            'profile': profile,
                            'resource_type': 'CodeArtifact Repository',
                            'resource_id': f'{domain_name}/{repo_name}',
                            'status': status,
                            'compliance_status': compliance_status,
                            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                            'recommendation': recommendation,
                            'details': {
                                'domain_name': domain_name,
                                'domain_owner': domain_owner,
                                'repository_name': repo_name,
                                'external_publishing_enabled': external_public_publishing_enabled,
                                'policy_document': policy_details
                            }
                        }
                        
                        findings.append(finding)
                        
                    except codeartifact_client.exceptions.ResourceNotFoundException:
                        # No policy found - repository is secure by default
                        finding = {
                            'region': region,
                            'profile': profile,
                            'resource_type': 'CodeArtifact Repository',
                            'resource_id': f'{domain_name}/{repo_name}',
                            'status': 'COMPLIANT',
                            'compliance_status': 'PASS',
                            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                            'recommendation': 'Repository has no permissions policy - secure by default',
                            'details': {
                                'domain_name': domain_name,
                                'domain_owner': domain_owner,
                                'repository_name': repo_name,
                                'external_publishing_enabled': False,
                                'policy_status': 'No policy found'
                            }
                        }
                        
                        findings.append(finding)
                        
                    except Exception as repo_error:
                        logger.error(f"Error checking repository {repo_name} in domain {domain_name}: {repo_error}")
                        continue
                        
            except Exception as domain_error:
                logger.error(f"Error processing domain {domain_name}: {domain_error}")
                continue
        
    except Exception as e:
        logger.error(f"Error in codeartifact_packages_external_public_publishing_disabled check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'CodeArtifact',
            'resource_id': f'check-error-{region}',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Review and remediate as needed'),
            'error': str(e)
        })
        
    return findings

def codeartifact_packages_external_public_publishing_disabled(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=codeartifact_packages_external_public_publishing_disabled_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = codeartifact_packages_external_public_publishing_disabled(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

#!/usr/bin/env python3
"""
iso27001_2022_aws - codebuild_project_artifact_encryption

Information should be classified and labelled in accordance with the classification scheme adopted by the organization.
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
        'compliance_name': 'iso27001_2022_aws',
        'function_name': 'codebuild_project_artifact_encryption',
        'id': 'ISO-27001-2022-A.8.2',
        'name': 'Information Classification',
        'description': 'Information should be classified and labelled in accordance with the classification scheme adopted by the organization.',
        'api_function': 'client = boto3.client(\'codebuild\')',
        'user_function': 'list_projects(), batch_get_projects()',
        'risk_level': 'HIGH',
        'recommendation': 'Enable encryption for CodeBuild project artifacts to protect sensitive build outputs'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('codebuild_project_artifact_encryption')

def codebuild_project_artifact_encryption_check(codebuild_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for codebuild_project_artifact_encryption.
    
    Args:
        codebuild_client: Boto3 CodeBuild client (auto-created by framework)
        region (str): AWS region (auto-managed by framework)
        profile (str): AWS profile name (auto-managed by framework)
        logger: Logger instance (auto-configured by framework)
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    try:
        # Get all CodeBuild projects
        response = codebuild_client.list_projects()
        project_names = response.get('projects', [])
        
        if not project_names:
            # No CodeBuild projects found
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'CodeBuild',
                'resource_id': f'no-projects-{region}',
                'status': 'COMPLIANT',
                'compliance_status': 'PASS',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                'recommendation': 'No CodeBuild projects found in this region',
                'details': {
                    'projects_count': 0,
                    'message': 'No CodeBuild projects found to check for artifact encryption'
                }
            }
            findings.append(finding)
            return findings
        
        # Get detailed project information in batches
        batch_size = 100  # AWS API limit
        for i in range(0, len(project_names), batch_size):
            batch = project_names[i:i + batch_size]
            
            try:
                projects_response = codebuild_client.batch_get_projects(names=batch)
                projects = projects_response.get('projects', [])
                
                for project in projects:
                    project_name = project.get('name', 'unknown')
                    project_arn = project.get('arn', 'unknown')
                    
                    # Check artifacts configuration
                    artifacts = project.get('artifacts', {})
                    artifact_type = artifacts.get('type', 'NO_ARTIFACTS')
                    
                    # Check for secondary artifacts as well
                    secondary_artifacts = project.get('secondaryArtifacts', [])
                    
                    # Initialize encryption status tracking
                    encryption_issues = []
                    all_artifacts_encrypted = True
                    total_artifacts = 0
                    
                    # Check primary artifacts
                    if artifact_type != 'NO_ARTIFACTS':
                        total_artifacts += 1
                        encryption_disabled = artifacts.get('encryptionDisabled', False)
                        
                        if encryption_disabled:
                            all_artifacts_encrypted = False
                            encryption_issues.append({
                                'artifact_type': 'primary',
                                'type': artifact_type,
                                'location': artifacts.get('location', 'unknown'),
                                'encryption_disabled': True
                            })
                    
                    # Check secondary artifacts
                    for idx, secondary_artifact in enumerate(secondary_artifacts):
                        total_artifacts += 1
                        secondary_type = secondary_artifact.get('type', 'unknown')
                        secondary_encryption_disabled = secondary_artifact.get('encryptionDisabled', False)
                        
                        if secondary_encryption_disabled:
                            all_artifacts_encrypted = False
                            encryption_issues.append({
                                'artifact_type': 'secondary',
                                'index': idx,
                                'type': secondary_type,
                                'location': secondary_artifact.get('location', 'unknown'),
                                'encryption_disabled': True
                            })
                    
                    # Determine compliance status
                    if total_artifacts == 0:
                        # No artifacts configured
                        status = 'COMPLIANT'
                        compliance_status = 'PASS'
                        risk_level = 'LOW'
                        recommendation = 'No artifacts configured for this project'
                    elif all_artifacts_encrypted:
                        # All artifacts are encrypted
                        status = 'COMPLIANT'
                        compliance_status = 'PASS'
                        risk_level = 'LOW'
                        recommendation = 'All artifacts are properly encrypted'
                    else:
                        # Some artifacts are not encrypted
                        status = 'NON_COMPLIANT'
                        compliance_status = 'FAIL'
                        risk_level = COMPLIANCE_DATA.get('risk_level', 'HIGH')
                        recommendation = COMPLIANCE_DATA.get('recommendation', 'Enable encryption for all CodeBuild project artifacts')
                    
                    finding = {
                        'region': region,
                        'profile': profile,
                        'resource_type': 'CodeBuild',
                        'resource_id': project_name,
                        'status': status,
                        'compliance_status': compliance_status,
                        'risk_level': risk_level,
                        'recommendation': recommendation,
                        'details': {
                            'project_name': project_name,
                            'project_arn': project_arn,
                            'total_artifacts': total_artifacts,
                            'primary_artifact_type': artifact_type,
                            'secondary_artifacts_count': len(secondary_artifacts),
                            'all_artifacts_encrypted': all_artifacts_encrypted,
                            'encryption_issues': encryption_issues,
                            'primary_artifacts': artifacts,
                            'secondary_artifacts': secondary_artifacts
                        }
                    }
                    
                    findings.append(finding)
                    
            except Exception as batch_error:
                logger.warning(f"Error getting project details for batch: {batch_error}")
                # Create error finding for this batch
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'CodeBuild',
                    'resource_id': f'batch-error-{i}',
                    'status': 'ERROR',
                    'compliance_status': 'ERROR',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                    'recommendation': 'Unable to check artifact encryption for some projects',
                    'details': {
                        'batch_projects': batch,
                        'error': str(batch_error)
                    }
                }
                findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in codebuild_project_artifact_encryption check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'CodeBuild',
            'resource_id': f'error-check-{region}',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable encryption for CodeBuild project artifacts'),
            'error': str(e)
        })
        
    return findings

def codebuild_project_artifact_encryption(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=codebuild_project_artifact_encryption_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = codebuild_project_artifact_encryption(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

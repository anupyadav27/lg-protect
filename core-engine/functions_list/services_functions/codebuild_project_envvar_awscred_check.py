#!/usr/bin/env python3
"""
iso27001_2022_aws - codebuild_project_envvar_awscred_check

Read and write access to source code, development tools and software libraries should be appropriately managed.
"""

import sys
import os
import json
import re
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
                    'recommendation': entry.get('Recommendation', 'Remove AWS credentials from environment variables and use IAM roles')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'iso27001_2022_aws',
        'function_name': 'codebuild_project_envvar_awscred_check',
        'id': 'ISO-27001-2022-A.8.2',
        'name': 'Source Code Access Management',
        'description': 'Read and write access to source code, development tools and software libraries should be appropriately managed.',
        'api_function': 'client = boto3.client(\'codebuild\')',
        'user_function': 'list_projects(), batch_get_projects()',
        'risk_level': 'HIGH',
        'recommendation': 'Remove AWS credentials from environment variables and use IAM roles'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('codebuild_project_envvar_awscred_check')

def detect_aws_credentials_in_env_vars(env_vars: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Detect AWS credentials in environment variables.
    
    Args:
        env_vars: List of environment variable dictionaries
        
    Returns:
        Dictionary with detection results
    """
    credentials_found = {
        'has_aws_credentials': False,
        'credential_types': [],
        'suspicious_variables': [],
        'risk_variables': []
    }
    
    if not env_vars:
        return credentials_found
    
    # AWS credential patterns
    aws_credential_patterns = [
        # AWS Access Key patterns
        (r'AKIA[0-9A-Z]{16}', 'AWS Access Key ID'),
        (r'ASIA[0-9A-Z]{16}', 'AWS Temporary Access Key ID'),
        # AWS Secret patterns (base64-like strings of specific lengths)
        (r'[A-Za-z0-9/+=]{40}', 'Potential AWS Secret Key'),
        # Session tokens
        (r'[A-Za-z0-9/+=]{100,}', 'Potential AWS Session Token'),
    ]
    
    # Suspicious environment variable names
    suspicious_env_names = [
        'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN',
        'AWS_ACCESS_KEY', 'AWS_SECRET_KEY', 'AWS_SECURITY_TOKEN',
        'AMAZON_ACCESS_KEY_ID', 'AMAZON_SECRET_ACCESS_KEY',
        'EC2_ACCESS_KEY', 'EC2_SECRET_KEY'
    ]
    
    for env_var in env_vars:
        var_name = env_var.get('name', '').upper()
        var_value = env_var.get('value', '')
        var_type = env_var.get('type', 'PLAINTEXT')
        
        # Check for suspicious variable names
        if var_name in suspicious_env_names:
            credentials_found['has_aws_credentials'] = True
            credentials_found['suspicious_variables'].append({
                'name': var_name,
                'type': var_type,
                'reason': 'AWS credential environment variable name'
            })
            
        # Check for AWS credential patterns in values (only for PLAINTEXT)
        if var_type == 'PLAINTEXT' and var_value:
            for pattern, credential_type in aws_credential_patterns:
                if re.search(pattern, var_value):
                    credentials_found['has_aws_credentials'] = True
                    if credential_type not in credentials_found['credential_types']:
                        credentials_found['credential_types'].append(credential_type)
                    
                    credentials_found['risk_variables'].append({
                        'name': var_name,
                        'type': var_type,
                        'credential_type': credential_type,
                        'reason': f'Contains pattern matching {credential_type}'
                    })
        
        # Check for generic key/secret patterns in variable names
        if any(keyword in var_name for keyword in ['KEY', 'SECRET', 'TOKEN', 'ACCESS', 'CREDENTIAL']):
            if 'AWS' in var_name or 'AMAZON' in var_name or 'EC2' in var_name:
                credentials_found['has_aws_credentials'] = True
                credentials_found['suspicious_variables'].append({
                    'name': var_name,
                    'type': var_type,
                    'reason': 'Suspicious AWS-related credential variable name'
                })
    
    return credentials_found

def codebuild_project_envvar_awscred_check(codebuild_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for codebuild_project_envvar_awscred_check.
    
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
                    'message': 'No CodeBuild projects found to check for AWS credentials in environment variables'
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
                    
                    # Check environment variables
                    environment = project.get('environment', {})
                    env_vars = environment.get('environmentVariables', [])
                    
                    # Detect AWS credentials in environment variables
                    credential_detection = detect_aws_credentials_in_env_vars(env_vars)
                    
                    # Determine compliance status
                    if credential_detection['has_aws_credentials']:
                        status = 'NON_COMPLIANT'
                        compliance_status = 'FAIL'
                        risk_level = COMPLIANCE_DATA.get('risk_level', 'HIGH')
                        recommendation = COMPLIANCE_DATA.get('recommendation', 'Remove AWS credentials from environment variables')
                    else:
                        status = 'COMPLIANT'
                        compliance_status = 'PASS'
                        risk_level = 'LOW'
                        recommendation = 'No AWS credentials detected in environment variables'
                    
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
                            'environment_variables_count': len(env_vars),
                            'has_aws_credentials': credential_detection['has_aws_credentials'],
                            'credential_types_detected': credential_detection['credential_types'],
                            'suspicious_variables': credential_detection['suspicious_variables'],
                            'risk_variables': credential_detection['risk_variables'],
                            'security_note': 'Environment variables should not contain hardcoded AWS credentials'
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
                    'recommendation': 'Unable to check environment variables for AWS credentials',
                    'details': {
                        'batch_projects': batch,
                        'error': str(batch_error)
                    }
                }
                findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in codebuild_project_envvar_awscred_check check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'CodeBuild',
            'resource_id': f'error-check-{region}',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Remove AWS credentials from environment variables'),
            'error': str(e)
        })
        
    return findings

def codebuild_project_envvar_awscred_check(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=codebuild_project_envvar_awscred_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = codebuild_project_envvar_awscred_check(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

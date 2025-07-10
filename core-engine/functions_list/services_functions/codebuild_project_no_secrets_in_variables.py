#!/usr/bin/env python3
"""
pci_3.2.1_aws - codebuild_project_no_secrets_in_variables

Many network devices and applications transmit unencrypted, readable passwords across the network and/or store passwords without encryption. A malicious individual can easily intercept unencrypted passwords during transmission using a "sniffer," or directly access unencrypted passwords in files where they are stored, and use this data to gain unauthorized access. Note: Testing Procedures 8.2.1.d and 8.2.1.e are additional procedures that only apply if the entity being assessed is a service provider.
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
                    'recommendation': entry.get('Recommendation', 'Remove secrets from environment variables and use secure methods like AWS Secrets Manager')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'pci_3.2.1_aws',
        'function_name': 'codebuild_project_no_secrets_in_variables',
        'id': 'PCI-DSS-3.2.1-8.2.1',
        'name': 'Secure Password Storage',
        'description': 'Many network devices and applications transmit unencrypted, readable passwords across the network and/or store passwords without encryption.',
        'api_function': 'client = boto3.client(\'codebuild\')',
        'user_function': 'list_projects(), batch_get_projects()',
        'risk_level': 'HIGH',
        'recommendation': 'Remove secrets from environment variables and use secure methods like AWS Secrets Manager'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('codebuild_project_no_secrets_in_variables')

def detect_potential_secrets(variable_name: str, variable_value: str) -> List[str]:
    """
    Detect potential secrets in environment variable names and values.
    
    Returns:
        List of detected secret types
    """
    secrets_found = []
    
    # Common secret patterns in variable names
    secret_patterns = [
        r'(?i)(password|passwd|pwd)',
        r'(?i)(secret|secrete)',
        r'(?i)(key|api_key|apikey)',
        r'(?i)(token|auth_token|access_token)',
        r'(?i)(credential|cred)',
        r'(?i)(private|priv)',
        r'(?i)(database_url|db_url)',
        r'(?i)(connection_string|conn_str)',
    ]
    
    # Check variable name for secret patterns
    for pattern in secret_patterns:
        if re.search(pattern, variable_name):
            secrets_found.append(f"Suspicious variable name: {variable_name}")
            break
    
    # Check variable value for common secret formats
    if variable_value:
        # Base64 encoded strings (potential secrets)
        if re.match(r'^[A-Za-z0-9+/]{20,}={0,2}$', variable_value) and len(variable_value) > 16:
            secrets_found.append("Potential Base64 encoded secret")
        
        # AWS Access Keys
        if re.match(r'^AKIA[0-9A-Z]{16}$', variable_value):
            secrets_found.append("AWS Access Key ID detected")
        
        # JWT tokens
        if re.match(r'^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$', variable_value):
            secrets_found.append("JWT token detected")
        
        # Generic high-entropy strings (potential secrets)
        if len(variable_value) > 20 and len(set(variable_value)) > 10:
            # Check entropy - secrets typically have high entropy
            import math
            from collections import Counter
            counter = Counter(variable_value)
            entropy = -sum((count/len(variable_value)) * math.log2(count/len(variable_value)) 
                          for count in counter.values())
            if entropy > 4.5:  # High entropy threshold
                secrets_found.append("High-entropy string (potential secret)")
    
    return secrets_found

def codebuild_project_no_secrets_in_variables_check(codebuild_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for codebuild_project_no_secrets_in_variables.
    
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
                    'message': 'No CodeBuild projects found to check for secrets in environment variables'
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
                    
                    # Check environment variables in project configuration
                    environment = project.get('environment', {})
                    env_variables = environment.get('environmentVariables', [])
                    
                    secrets_detected = []
                    total_variables = len(env_variables)
                    
                    for env_var in env_variables:
                        var_name = env_var.get('name', '')
                        var_value = env_var.get('value', '')
                        var_type = env_var.get('type', 'PLAINTEXT')
                        
                        # Only check PLAINTEXT variables for secrets
                        # PARAMETER_STORE and SECRETS_MANAGER are considered secure
                        if var_type == 'PLAINTEXT':
                            detected_secrets = detect_potential_secrets(var_name, var_value)
                            if detected_secrets:
                                secrets_detected.append({
                                    'variable_name': var_name,
                                    'variable_type': var_type,
                                    'secrets_found': detected_secrets,
                                    'value_length': len(var_value) if var_value else 0
                                })
                    
                    # Determine compliance status
                    if secrets_detected:
                        status = 'NON_COMPLIANT'
                        compliance_status = 'FAIL'
                        risk_level = COMPLIANCE_DATA.get('risk_level', 'HIGH')
                        recommendation = COMPLIANCE_DATA.get('recommendation', 'Remove secrets from environment variables')
                    else:
                        status = 'COMPLIANT'
                        compliance_status = 'PASS'
                        risk_level = 'LOW'
                        recommendation = 'No secrets detected in environment variables'
                    
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
                            'total_environment_variables': total_variables,
                            'secrets_detected_count': len(secrets_detected),
                            'secrets_detected': secrets_detected,
                            'secure_variable_types_used': [
                                var.get('type') for var in env_variables 
                                if var.get('type') in ['PARAMETER_STORE', 'SECRETS_MANAGER']
                            ]
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
                    'recommendation': 'Unable to check environment variables for some projects',
                    'details': {
                        'batch_projects': batch,
                        'error': str(batch_error)
                    }
                }
                findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in codebuild_project_no_secrets_in_variables check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'CodeBuild',
            'resource_id': f'error-check-{region}',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Remove secrets from environment variables'),
            'error': str(e)
        })
        
    return findings

def codebuild_project_no_secrets_in_variables(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=codebuild_project_no_secrets_in_variables_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = codebuild_project_no_secrets_in_variables(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

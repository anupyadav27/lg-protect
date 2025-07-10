#!/usr/bin/env python3
"""
iso27001_2022_aws - codebuild_project_s3_logs_encrypted

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
                    'risk_level': entry.get('Risk Level', 'MEDIUM'),
                    'recommendation': entry.get('Recommendation', 'Review and remediate as needed')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'iso27001_2022_aws',
        'function_name': 'codebuild_project_s3_logs_encrypted',
        'id': 'A.10.1.1',
        'name': 'CodeBuild projects should have S3 logs encrypted',
        'description': 'Rules for the effective use of cryptography, including cryptographic key management, should be defined and implemented',
        'api_function': 'client = boto3.client("codebuild")',
        'user_function': 'list_projects(), batch_get_projects()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Enable encryption for CodeBuild project S3 logs to protect build log data'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('codebuild_project_s3_logs_encrypted')

def codebuild_project_s3_logs_encrypted_check(codebuild_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for codebuild_project_s3_logs_encrypted.
    
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
        logger.info(f"Checking CodeBuild project S3 logs encryption in region {region}")
        
        # Get all CodeBuild projects
        projects_response = codebuild_client.list_projects()
        project_names = projects_response.get('projects', [])
        
        if not project_names:
            logger.info(f"No CodeBuild projects found in region {region}")
            return findings
        
        # Process projects in batches (max 100 per batch_get_projects call)
        batch_size = 100
        for i in range(0, len(project_names), batch_size):
            batch_names = project_names[i:i + batch_size]
            
            try:
                # Get detailed project information
                projects_details = codebuild_client.batch_get_projects(names=batch_names)
                projects = projects_details.get('projects', [])
                
                for project in projects:
                    project_name = project.get('name', 'unknown')
                    project_arn = project.get('arn', 'unknown')
                    service_role = project.get('serviceRole', 'unknown')
                    created = project.get('created', '')
                    last_modified = project.get('lastModified', '')
                    
                    # Get logs configuration
                    logs_config = project.get('logsConfig', {})
                    s3_logs = logs_config.get('s3Logs', {})
                    cloudwatch_logs = logs_config.get('cloudWatchLogs', {})
                    
                    # Check S3 logs configuration
                    s3_logs_status = s3_logs.get('status', 'DISABLED')
                    s3_location = s3_logs.get('location', '')
                    s3_encryption_disabled = s3_logs.get('encryptionDisabled', True)
                    
                    # Check CloudWatch logs as additional context
                    cw_logs_status = cloudwatch_logs.get('status', 'DISABLED')
                    cw_group_name = cloudwatch_logs.get('groupName', '')
                    
                    # Get source configuration for context
                    source = project.get('source', {})
                    source_type = source.get('type', 'unknown')
                    source_location = source.get('location', '')
                    
                    # Get environment information
                    environment = project.get('environment', {})
                    environment_type = environment.get('type', 'unknown')
                    compute_type = environment.get('computeType', 'unknown')
                    
                    if s3_logs_status == 'ENABLED':
                        if not s3_encryption_disabled:
                            # Compliant: S3 logs are enabled and encrypted
                            finding = {
                                'region': region,
                                'profile': profile,
                                'resource_type': 'CodeBuild Project',
                                'resource_id': project_name,
                                'status': 'COMPLIANT',
                                'compliance_status': 'PASS',
                                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                                'recommendation': COMPLIANCE_DATA.get('recommendation', 'S3 logs encryption is properly enabled'),
                                'details': {
                                    'project_name': project_name,
                                    'project_arn': project_arn,
                                    'service_role': service_role,
                                    's3_logs_status': s3_logs_status,
                                    's3_location': s3_location,
                                    's3_encryption_disabled': s3_encryption_disabled,
                                    'cloudwatch_logs_status': cw_logs_status,
                                    'cloudwatch_group_name': cw_group_name,
                                    'source_type': source_type,
                                    'environment_type': environment_type,
                                    'compute_type': compute_type,
                                    'created': created.isoformat() if created else '',
                                    'last_modified': last_modified.isoformat() if last_modified else ''
                                }
                            }
                        else:
                            # Non-compliant: S3 logs are enabled but encryption is disabled
                            finding = {
                                'region': region,
                                'profile': profile,
                                'resource_type': 'CodeBuild Project',
                                'resource_id': project_name,
                                'status': 'NON_COMPLIANT',
                                'compliance_status': 'FAIL',
                                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                                'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable S3 logs encryption for this project'),
                                'details': {
                                    'project_name': project_name,
                                    'project_arn': project_arn,
                                    'service_role': service_role,
                                    's3_logs_status': s3_logs_status,
                                    's3_location': s3_location,
                                    's3_encryption_disabled': s3_encryption_disabled,
                                    'issue': 'S3 logs are enabled but encryption is disabled',
                                    'cloudwatch_logs_status': cw_logs_status,
                                    'security_risk': 'Build logs stored in S3 without encryption may expose sensitive information',
                                    'remediation_steps': [
                                        'Navigate to CodeBuild console',
                                        'Edit the project configuration',
                                        'Go to Logs section',
                                        'Enable S3 logs encryption',
                                        'Specify appropriate S3 bucket with encryption',
                                        'Update project settings'
                                    ],
                                    'source_type': source_type,
                                    'environment_type': environment_type,
                                    'compute_type': compute_type,
                                    'created': created.isoformat() if created else '',
                                    'last_modified': last_modified.isoformat() if last_modified else ''
                                }
                            }
                    else:
                        # S3 logs are disabled - check if any logs are configured
                        if cw_logs_status == 'ENABLED':
                            # Compliant: Using CloudWatch logs instead of S3
                            finding = {
                                'region': region,
                                'profile': profile,
                                'resource_type': 'CodeBuild Project',
                                'resource_id': project_name,
                                'status': 'COMPLIANT',
                                'compliance_status': 'PASS',
                                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                                'recommendation': COMPLIANCE_DATA.get('recommendation', 'Project uses CloudWatch logs which are encrypted by default'),
                                'details': {
                                    'project_name': project_name,
                                    'project_arn': project_arn,
                                    'service_role': service_role,
                                    's3_logs_status': s3_logs_status,
                                    'cloudwatch_logs_status': cw_logs_status,
                                    'cloudwatch_group_name': cw_group_name,
                                    'note': 'S3 logs not enabled, using CloudWatch logs (encrypted by default)',
                                    'source_type': source_type,
                                    'environment_type': environment_type,
                                    'compute_type': compute_type,
                                    'created': created.isoformat() if created else '',
                                    'last_modified': last_modified.isoformat() if last_modified else ''
                                }
                            }
                        else:
                            # Warning: No logs configured at all
                            finding = {
                                'region': region,
                                'profile': profile,
                                'resource_type': 'CodeBuild Project',
                                'resource_id': project_name,
                                'status': 'NON_COMPLIANT',
                                'compliance_status': 'FAIL',
                                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                                'recommendation': COMPLIANCE_DATA.get('recommendation', 'Configure encrypted logging for this project'),
                                'details': {
                                    'project_name': project_name,
                                    'project_arn': project_arn,
                                    'service_role': service_role,
                                    's3_logs_status': s3_logs_status,
                                    'cloudwatch_logs_status': cw_logs_status,
                                    'issue': 'No logging is configured for this CodeBuild project',
                                    'security_risk': 'Without logging, build activities and potential security issues cannot be monitored',
                                    'remediation_steps': [
                                        'Navigate to CodeBuild console',
                                        'Edit the project configuration',
                                        'Enable either S3 logs with encryption or CloudWatch logs',
                                        'Configure appropriate log retention policies',
                                        'Test logging functionality'
                                    ],
                                    'source_type': source_type,
                                    'environment_type': environment_type,
                                    'compute_type': compute_type,
                                    'created': created.isoformat() if created else '',
                                    'last_modified': last_modified.isoformat() if last_modified else ''
                                }
                            }
                    
                    findings.append(finding)
                    
            except Exception as e:
                logger.error(f"Error checking CodeBuild projects batch in {region}: {e}")
                for project_name in batch_names:
                    findings.append({
                        'region': region,
                        'profile': profile,
                        'resource_type': 'CodeBuild Project',
                        'resource_id': project_name,
                        'status': 'ERROR',
                        'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                        'recommendation': COMPLIANCE_DATA.get('recommendation', 'Review project configuration'),
                        'error': str(e)
                    })
        
    except Exception as e:
        logger.error(f"Error in codebuild_project_s3_logs_encrypted check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'CodeBuild Project',
            'status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Review and remediate as needed'),
            'error': str(e)
        })
        
    return findings

def codebuild_project_s3_logs_encrypted(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=codebuild_project_s3_logs_encrypted_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = codebuild_project_s3_logs_encrypted(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

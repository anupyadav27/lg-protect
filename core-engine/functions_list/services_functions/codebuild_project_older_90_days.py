#!/usr/bin/env python3
"""
iso27001_2022_aws - codebuild_project_older_90_days

Read and write access to source code, development tools and software libraries should be appropriately managed.
"""

import sys
import os
import json
from typing import Dict, List, Any
from datetime import datetime, timedelta

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
        'function_name': 'codebuild_project_older_90_days',
        'id': 'ISO-27001-2022-A.8.2',
        'name': 'Source Code Access Management',
        'description': 'Read and write access to source code, development tools and software libraries should be appropriately managed.',
        'api_function': 'client = boto3.client(\'codebuild\')',
        'user_function': 'list_projects(), batch_get_projects()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Review and manage CodeBuild projects older than 90 days to ensure they are still needed and properly maintained'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('codebuild_project_older_90_days')

def codebuild_project_older_90_days_check(codebuild_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for codebuild_project_older_90_days.
    
    Args:
        codebuild_client: Boto3 CodeBuild client (auto-created by framework)
        region (str): AWS region (auto-managed by framework)
        profile (str): AWS profile name (auto-managed by framework)
        logger: Logger instance (auto-configured by framework)
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    # Define the 90-day threshold
    ninety_days_ago = datetime.utcnow() - timedelta(days=90)
    
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
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                'recommendation': 'No CodeBuild projects found in this region',
                'details': {
                    'projects_count': 0,
                    'message': 'No CodeBuild projects found to check for age compliance'
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
                    created_time = project.get('created')
                    last_modified = project.get('lastModified')
                    
                    # Calculate project age
                    if created_time:
                        if isinstance(created_time, str):
                            # Parse string datetime
                            try:
                                created_datetime = datetime.fromisoformat(created_time.replace('Z', '+00:00'))
                            except:
                                created_datetime = datetime.strptime(created_time, '%Y-%m-%dT%H:%M:%S.%fZ')
                        else:
                            created_datetime = created_time
                        
                        age_days = (datetime.utcnow() - created_datetime.replace(tzinfo=None)).days
                        is_older_than_90_days = created_datetime.replace(tzinfo=None) < ninety_days_ago
                    else:
                        age_days = None
                        is_older_than_90_days = False
                    
                    # Calculate days since last modification
                    if last_modified:
                        if isinstance(last_modified, str):
                            try:
                                last_modified_datetime = datetime.fromisoformat(last_modified.replace('Z', '+00:00'))
                            except:
                                last_modified_datetime = datetime.strptime(last_modified, '%Y-%m-%dT%H:%M:%S.%fZ')
                        else:
                            last_modified_datetime = last_modified
                        
                        days_since_modified = (datetime.utcnow() - last_modified_datetime.replace(tzinfo=None)).days
                    else:
                        days_since_modified = age_days
                    
                    # Determine compliance status
                    if is_older_than_90_days:
                        status = 'NON_COMPLIANT'
                        compliance_status = 'FAIL'
                        risk_level = COMPLIANCE_DATA.get('risk_level', 'MEDIUM')
                        recommendation = COMPLIANCE_DATA.get('recommendation', 'Review and manage old CodeBuild projects')
                    else:
                        status = 'COMPLIANT'
                        compliance_status = 'PASS'
                        risk_level = 'LOW'
                        recommendation = 'Project is within acceptable age limits'
                    
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
                            'created_time': created_time.isoformat() if created_time else 'unknown',
                            'last_modified': last_modified.isoformat() if last_modified else 'unknown',
                            'age_days': age_days,
                            'days_since_modified': days_since_modified,
                            'is_older_than_90_days': is_older_than_90_days,
                            'threshold_date': ninety_days_ago.isoformat()
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
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                    'recommendation': 'Unable to check project age for some projects',
                    'details': {
                        'batch_projects': batch,
                        'error': str(batch_error)
                    }
                }
                findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in codebuild_project_older_90_days check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'CodeBuild',
            'resource_id': f'error-check-{region}',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Review and manage old CodeBuild projects'),
            'error': str(e)
        })
        
    return findings

def codebuild_project_older_90_days(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=codebuild_project_older_90_days_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = codebuild_project_older_90_days(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

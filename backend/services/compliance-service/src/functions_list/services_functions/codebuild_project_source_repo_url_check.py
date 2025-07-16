#!/usr/bin/env python3
"""
iso27001_2022_aws - codebuild_project_source_repo_url_check

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
                    'risk_level': entry.get('Risk Level', 'MEDIUM'),
                    'recommendation': entry.get('Recommendation', 'Review and remediate as needed')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'iso27001_2022_aws',
        'function_name': 'codebuild_project_source_repo_url_check',
        'id': 'ISO-27001-2022-A.8.2',
        'name': 'Source Code Access Management',
        'description': 'Read and write access to source code, development tools and software libraries should be appropriately managed.',
        'api_function': 'client = boto3.client(\'codebuild\')',
        'user_function': 'list_projects(), batch_get_projects()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Ensure CodeBuild projects use secure and trusted source repository URLs'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('codebuild_project_source_repo_url_check')

def analyze_source_repo_url(location: str, source_type: str) -> Dict[str, Any]:
    """
    Analyze source repository URL for security concerns.
    
    Returns:
        Dictionary with analysis results
    """
    analysis = {
        'is_secure': True,
        'issues': [],
        'url_type': 'unknown',
        'protocol': 'unknown'
    }
    
    if not location:
        analysis['is_secure'] = False
        analysis['issues'].append('No source location specified')
        return analysis
    
    # Check for HTTP vs HTTPS
    if location.startswith('http://'):
        analysis['is_secure'] = False
        analysis['protocol'] = 'http'
        analysis['issues'].append('Uses insecure HTTP protocol instead of HTTPS')
    elif location.startswith('https://'):
        analysis['protocol'] = 'https'
    elif location.startswith('git://'):
        analysis['is_secure'] = False
        analysis['protocol'] = 'git'
        analysis['issues'].append('Uses insecure git:// protocol')
    
    # Identify repository type
    if 'github.com' in location:
        analysis['url_type'] = 'github'
    elif 'bitbucket.org' in location:
        analysis['url_type'] = 'bitbucket'
    elif 'gitlab.com' in location:
        analysis['url_type'] = 'gitlab'
    elif 'codecommit' in location:
        analysis['url_type'] = 'codecommit'
    elif re.search(r'\.amazonaws\.com', location):
        analysis['url_type'] = 'aws_service'
    else:
        analysis['url_type'] = 'other'
    
    # Check for suspicious patterns
    suspicious_patterns = [
        r'(?i)(temp|tmp|test|demo)',  # Temporary/test repositories
        r'(?i)(localhost|127\.0\.0\.1|0\.0\.0\.0)',  # Local development
        r'(?i)(\.onion)',  # Tor hidden services
        r'(?i)(raw\.githubusercontent\.com)',  # Direct file access
    ]
    
    for pattern in suspicious_patterns:
        if re.search(pattern, location):
            analysis['is_secure'] = False
            analysis['issues'].append(f'Suspicious pattern detected: {pattern}')
    
    # Check for IP addresses instead of domain names
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    if re.search(ip_pattern, location):
        analysis['is_secure'] = False
        analysis['issues'].append('Uses IP address instead of domain name')
    
    return analysis

def codebuild_project_source_repo_url_check_check(codebuild_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for codebuild_project_source_repo_url_check.
    
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
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                'recommendation': 'No CodeBuild projects found in this region',
                'details': {
                    'projects_count': 0,
                    'message': 'No CodeBuild projects found to check source repository URLs'
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
                    
                    # Check source configuration
                    source = project.get('source', {})
                    source_type = source.get('type', 'unknown')
                    location = source.get('location', '')
                    
                    # Analyze the source repository URL
                    url_analysis = analyze_source_repo_url(location, source_type)
                    
                    # Determine compliance status
                    if url_analysis['is_secure']:
                        status = 'COMPLIANT'
                        compliance_status = 'PASS'
                        risk_level = 'LOW'
                        recommendation = 'Source repository URL is secure and follows best practices'
                    else:
                        status = 'NON_COMPLIANT'
                        compliance_status = 'FAIL'
                        risk_level = COMPLIANCE_DATA.get('risk_level', 'MEDIUM')
                        recommendation = COMPLIANCE_DATA.get('recommendation', 'Review and secure source repository URL')
                    
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
                            'source_type': source_type,
                            'source_location': location,
                            'url_analysis': url_analysis,
                            'security_issues': url_analysis['issues'],
                            'url_type': url_analysis['url_type'],
                            'protocol': url_analysis['protocol']
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
                    'recommendation': 'Unable to check source repository URLs for some projects',
                    'details': {
                        'batch_projects': batch,
                        'error': str(batch_error)
                    }
                }
                findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in codebuild_project_source_repo_url_check check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'CodeBuild',
            'resource_id': f'error-check-{region}',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Ensure CodeBuild projects use secure source repository URLs'),
            'error': str(e)
        })
        
    return findings

def codebuild_project_source_repo_url_check(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=codebuild_project_source_repo_url_check_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = codebuild_project_source_repo_url_check(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

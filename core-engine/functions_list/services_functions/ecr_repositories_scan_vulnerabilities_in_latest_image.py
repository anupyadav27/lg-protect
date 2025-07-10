#!/usr/bin/env python3
"""
iso27001_2022_aws - ecr_repositories_scan_vulnerabilities_in_latest_image

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
                    'recommendation': entry.get('Recommendation', 'Scan latest images for vulnerabilities and remediate any findings')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'iso27001_2022_aws',
        'function_name': 'ecr_repositories_scan_vulnerabilities_in_latest_image',
        'id': 'ECR.3',
        'name': 'ECR repositories should scan latest images for vulnerabilities',
        'description': 'Security mechanisms, service levels and service requirements of network services should be identified, implemented and monitored.',
        'api_function': 'client = boto3.client(\'ecr\')',
        'user_function': 'describe_repositories(), describe_image_scan_findings()',
        'risk_level': 'HIGH',
        'recommendation': 'Scan latest images for vulnerabilities and remediate any findings'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('ecr_repositories_scan_vulnerabilities_in_latest_image')

def ecr_repositories_scan_vulnerabilities_in_latest_image_check(ecr_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for ecr_repositories_scan_vulnerabilities_in_latest_image.
    
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
                    # Get images in the repository
                    images_response = ecr_client.describe_images(
                        registryId=registry_id,
                        repositoryName=repository_name,
                        maxResults=1,
                        filter={'tagStatus': 'TAGGED'}
                    )
                    
                    images = images_response.get('imageDetails', [])
                    
                    if not images:
                        findings.append({
                            'region': region,
                            'profile': profile,
                            'resource_type': 'ECR Repository',
                            'resource_id': repository_name,
                            'status': 'NON_COMPLIANT',
                            'compliance_status': 'FAIL',
                            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Add images to repository and scan for vulnerabilities'),
                            'details': {
                                'repository_name': repository_name,
                                'repository_arn': repository_arn,
                                'registry_id': registry_id,
                                'issue': 'No tagged images found in repository'
                            }
                        })
                        continue
                    
                    # Get the latest image (first one when sorted by push date)
                    latest_image = max(images, key=lambda x: x.get('imagePushedAt', 0))
                    image_digest = latest_image.get('imageDigest')
                    image_tags = latest_image.get('imageTags', [])
                    
                    try:
                        # Check scan results for the latest image
                        scan_results = ecr_client.describe_image_scan_findings(
                            registryId=registry_id,
                            repositoryName=repository_name,
                            imageId={'imageDigest': image_digest}
                        )
                        
                        scan_status = scan_results.get('imageScanStatus', {}).get('status', 'UNDEFINED')
                        findings_summary = scan_results.get('imageScanFindings', {}).get('findingCounts', {})
                        
                        critical_count = findings_summary.get('CRITICAL', 0)
                        high_count = findings_summary.get('HIGH', 0)
                        medium_count = findings_summary.get('MEDIUM', 0)
                        low_count = findings_summary.get('LOW', 0)
                        informational_count = findings_summary.get('INFORMATIONAL', 0)
                        
                        total_vulnerabilities = critical_count + high_count + medium_count + low_count + informational_count
                        
                        if scan_status == 'COMPLETE':
                            if critical_count > 0 or high_count > 0:
                                findings.append({
                                    'region': region,
                                    'profile': profile,
                                    'resource_type': 'ECR Repository',
                                    'resource_id': repository_name,
                                    'status': 'NON_COMPLIANT',
                                    'compliance_status': 'FAIL',
                                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Remediate critical and high severity vulnerabilities'),
                                    'details': {
                                        'repository_name': repository_name,
                                        'repository_arn': repository_arn,
                                        'registry_id': registry_id,
                                        'image_digest': image_digest,
                                        'image_tags': image_tags,
                                        'scan_status': scan_status,
                                        'critical_vulnerabilities': critical_count,
                                        'high_vulnerabilities': high_count,
                                        'medium_vulnerabilities': medium_count,
                                        'low_vulnerabilities': low_count,
                                        'total_vulnerabilities': total_vulnerabilities,
                                        'issue': f'Latest image has {critical_count} critical and {high_count} high severity vulnerabilities'
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
                                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Continue monitoring for vulnerabilities'),
                                    'details': {
                                        'repository_name': repository_name,
                                        'repository_arn': repository_arn,
                                        'registry_id': registry_id,
                                        'image_digest': image_digest,
                                        'image_tags': image_tags,
                                        'scan_status': scan_status,
                                        'critical_vulnerabilities': critical_count,
                                        'high_vulnerabilities': high_count,
                                        'medium_vulnerabilities': medium_count,
                                        'low_vulnerabilities': low_count,
                                        'total_vulnerabilities': total_vulnerabilities
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
                                'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                                'recommendation': COMPLIANCE_DATA.get('recommendation', 'Complete vulnerability scan for latest image'),
                                'details': {
                                    'repository_name': repository_name,
                                    'repository_arn': repository_arn,
                                    'registry_id': registry_id,
                                    'image_digest': image_digest,
                                    'image_tags': image_tags,
                                    'scan_status': scan_status,
                                    'issue': f'Image scan status is {scan_status}, not COMPLETE'
                                }
                            })
                            
                    except ecr_client.exceptions.ScanNotFoundException:
                        findings.append({
                            'region': region,
                            'profile': profile,
                            'resource_type': 'ECR Repository',
                            'resource_id': repository_name,
                            'status': 'NON_COMPLIANT',
                            'compliance_status': 'FAIL',
                            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Initiate vulnerability scan for latest image'),
                            'details': {
                                'repository_name': repository_name,
                                'repository_arn': repository_arn,
                                'registry_id': registry_id,
                                'image_digest': image_digest,
                                'image_tags': image_tags,
                                'issue': 'No scan results found for latest image'
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
                        'recommendation': COMPLIANCE_DATA.get('recommendation', 'Resolve errors and scan for vulnerabilities'),
                        'error': str(repo_error)
                    })
                    
    except Exception as e:
        logger.error(f"Error in ecr_repositories_scan_vulnerabilities_in_latest_image check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'ECR Repository',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Resolve errors and scan for vulnerabilities'),
            'error': str(e)
        })
        
    return findings

def ecr_repositories_scan_vulnerabilities_in_latest_image(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=ecr_repositories_scan_vulnerabilities_in_latest_image_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = ecr_repositories_scan_vulnerabilities_in_latest_image(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

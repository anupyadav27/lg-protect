#!/usr/bin/env python3
"""
aws_foundational_security_best_practices_aws - cloudfront_distributions_using_deprecated_ssl_protocols

CloudFront distributions should not use deprecated SSL protocols between edge locations and custom origins
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
                    'recommendation': entry.get('Recommendation', 'Review and remediate as needed')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'aws_foundational_security_best_practices_aws',
        'function_name': 'cloudfront_distributions_using_deprecated_ssl_protocols',
        'id': 'CloudFront.10',
        'name': 'CloudFront distributions should not use deprecated SSL protocols between edge locations and custom origins',
        'description': 'This control checks if Amazon CloudFront distributions are using deprecated SSL protocols for HTTPS communication.',
        'api_function': 'client = boto3.client("cloudfront")',
        'user_function': 'list_distributions(), get_distribution_config(), get_distribution(), update_distribution()',
        'risk_level': 'HIGH',
        'recommendation': 'Remove deprecated SSL protocols (SSLv3) from CloudFront distribution custom origin configurations'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('cloudfront_distributions_using_deprecated_ssl_protocols')

def cloudfront_distributions_using_deprecated_ssl_protocols_check(cloudfront_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for cloudfront_distributions_using_deprecated_ssl_protocols.
    
    Args:
        cloudfront_client: Boto3 CloudFront client (auto-created by framework)
        region (str): AWS region (auto-managed by framework)
        profile (str): AWS profile name (auto-managed by framework)
        logger: Logger instance (auto-configured by framework)
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    try:
        # Get all CloudFront distributions
        paginator = cloudfront_client.get_paginator('list_distributions')
        
        for page in paginator.paginate():
            distributions = page.get('DistributionList', {}).get('Items', [])
            
            for distribution in distributions:
                distribution_id = distribution.get('Id')
                distribution_arn = distribution.get('ARN')
                domain_name = distribution.get('DomainName')
                
                try:
                    # Get detailed distribution configuration
                    config_response = cloudfront_client.get_distribution_config(Id=distribution_id)
                    config = config_response.get('DistributionConfig', {})
                    
                    # Check origins for deprecated SSL protocols
                    origins = config.get('Origins', {}).get('Items', [])
                    has_deprecated_ssl = False
                    deprecated_origins = []
                    
                    for origin in origins:
                        custom_origin_config = origin.get('CustomOriginConfig', {})
                        if custom_origin_config:
                            # Check for deprecated SSL protocols
                            origin_ssl_protocols = custom_origin_config.get('OriginSslProtocols', {})
                            ssl_protocols = origin_ssl_protocols.get('Items', [])
                            
                            # Check for deprecated protocols (SSLv3, TLSv1, TLSv1.1)
                            deprecated_protocols = []
                            for protocol in ssl_protocols:
                                if protocol in ['SSLv3', 'TLSv1', 'TLSv1.1']:
                                    deprecated_protocols.append(protocol)
                            
                            if deprecated_protocols:
                                has_deprecated_ssl = True
                                deprecated_origins.append({
                                    'origin_id': origin.get('Id'),
                                    'domain_name': origin.get('DomainName'),
                                    'deprecated_protocols': deprecated_protocols
                                })
                    
                    # Create finding based on SSL protocol check
                    if has_deprecated_ssl:
                        finding = {
                            'region': region,
                            'profile': profile,
                            'resource_type': 'CloudFront Distribution',
                            'resource_id': distribution_id,
                            'resource_arn': distribution_arn,
                            'status': 'NON_COMPLIANT',
                            'compliance_status': 'FAIL',
                            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Remove deprecated SSL protocols from CloudFront distribution custom origin configurations'),
                            'details': {
                                'distribution_id': distribution_id,
                                'distribution_arn': distribution_arn,
                                'domain_name': domain_name,
                                'deprecated_origins': deprecated_origins,
                                'total_origins_with_deprecated_ssl': len(deprecated_origins)
                            }
                        }
                    else:
                        finding = {
                            'region': region,
                            'profile': profile,
                            'resource_type': 'CloudFront Distribution',
                            'resource_id': distribution_id,
                            'resource_arn': distribution_arn,
                            'status': 'COMPLIANT',
                            'compliance_status': 'PASS',
                            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                            'recommendation': COMPLIANCE_DATA.get('recommendation', 'No action required'),
                            'details': {
                                'distribution_id': distribution_id,
                                'distribution_arn': distribution_arn,
                                'domain_name': domain_name,
                                'origins_checked': len(origins),
                                'deprecated_ssl_found': False
                            }
                        }
                    
                    findings.append(finding)
                    
                except Exception as config_error:
                    logger.error(f"Error getting distribution config for {distribution_id}: {config_error}")
                    findings.append({
                        'region': region,
                        'profile': profile,
                        'resource_type': 'CloudFront Distribution',
                        'resource_id': distribution_id,
                        'status': 'ERROR',
                        'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                        'recommendation': COMPLIANCE_DATA.get('recommendation', 'Review and remediate as needed'),
                        'error': f"Failed to get distribution configuration: {str(config_error)}"
                    })
        
        # If no distributions found, log this information
        if not findings:
            logger.info(f"No CloudFront distributions found in region {region} for profile {profile}")
            
    except Exception as e:
        logger.error(f"Error in cloudfront_distributions_using_deprecated_ssl_protocols check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'CloudFront Distribution',
            'status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Review and remediate as needed'),
            'error': str(e)
        })
        
    return findings

def cloudfront_distributions_using_deprecated_ssl_protocols(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=cloudfront_distributions_using_deprecated_ssl_protocols_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = cloudfront_distributions_using_deprecated_ssl_protocols(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

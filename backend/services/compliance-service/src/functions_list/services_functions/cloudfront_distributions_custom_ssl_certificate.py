#!/usr/bin/env python3
"""
aws_foundational_security_best_practices_aws - cloudfront_distributions_custom_ssl_certificate

CloudFront distributions should use custom SSL certificates when serving HTTPS content
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
                    'recommendation': entry.get('Recommendation', 'Use custom SSL certificates for CloudFront distributions')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'aws_foundational_security_best_practices_aws',
        'function_name': 'cloudfront_distributions_custom_ssl_certificate',
        'id': 'CloudFront.7',
        'name': 'CloudFront distributions should use custom SSL certificates',
        'description': 'This control checks whether CloudFront distributions use custom SSL certificates.',
        'api_function': 'client = boto3.client(\'cloudfront\')',
        'user_function': 'list_distributions(), get_distribution_config()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Use custom SSL certificates for CloudFront distributions'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('cloudfront_distributions_custom_ssl_certificate')

def cloudfront_distributions_custom_ssl_certificate_check(cloudfront_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for cloudfront_distributions_custom_ssl_certificate.
    
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
        response = cloudfront_client.list_distributions()
        
        if 'DistributionList' in response and 'Items' in response['DistributionList']:
            distributions = response['DistributionList']['Items']
            
            for distribution in distributions:
                distribution_id = distribution['Id']
                domain_name = distribution['DomainName']
                
                # Get detailed distribution configuration
                config_response = cloudfront_client.get_distribution_config(Id=distribution_id)
                distribution_config = config_response['DistributionConfig']
                
                # Check viewer certificate configuration
                viewer_certificate = distribution_config.get('ViewerCertificate', {})
                
                # Check certificate source and type
                certificate_source = viewer_certificate.get('CertificateSource', 'cloudfront')
                ssl_support_method = viewer_certificate.get('SSLSupportMethod', 'vip')
                minimum_protocol_version = viewer_certificate.get('MinimumProtocolVersion', 'SSLv3')
                
                # Check for custom certificate
                acm_certificate_arn = viewer_certificate.get('ACMCertificateArn', '')
                iam_certificate_id = viewer_certificate.get('IAMCertificateId', '')
                cloudfront_default_certificate = viewer_certificate.get('CloudFrontDefaultCertificate', False)
                
                # Determine if using custom SSL certificate
                uses_custom_certificate = bool(acm_certificate_arn or iam_certificate_id)
                uses_cloudfront_default = cloudfront_default_certificate
                
                # Check if distribution has custom domain names (aliases)
                aliases = distribution_config.get('Aliases', {}).get('Items', [])
                has_custom_domains = len(aliases) > 0
                
                # Determine compliance status
                if has_custom_domains and uses_custom_certificate:
                    status = 'COMPLIANT'
                    compliance_status = 'PASS'
                    note = 'Using custom SSL certificate with custom domains'
                elif not has_custom_domains and uses_cloudfront_default:
                    status = 'COMPLIANT'
                    compliance_status = 'PASS'
                    note = 'Using CloudFront default certificate (no custom domains)'
                elif has_custom_domains and not uses_custom_certificate:
                    status = 'NON_COMPLIANT'
                    compliance_status = 'FAIL'
                    note = 'Custom domains configured but not using custom SSL certificate'
                else:
                    status = 'COMPLIANT'
                    compliance_status = 'PASS'
                    note = 'Standard configuration'
                
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'CloudFront Distribution',
                    'resource_id': distribution_id,
                    'status': status,
                    'compliance_status': compliance_status,
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Use custom SSL certificates for CloudFront distributions'),
                    'details': {
                        'distribution_id': distribution_id,
                        'domain_name': domain_name,
                        'certificate_source': certificate_source,
                        'uses_custom_certificate': uses_custom_certificate,
                        'uses_cloudfront_default': uses_cloudfront_default,
                        'has_custom_domains': has_custom_domains,
                        'custom_domains_count': len(aliases),
                        'custom_domains': aliases[:5],  # Limit to first 5
                        'acm_certificate_arn': acm_certificate_arn if acm_certificate_arn else 'None',
                        'iam_certificate_id': iam_certificate_id if iam_certificate_id else 'None',
                        'ssl_support_method': ssl_support_method,
                        'minimum_protocol_version': minimum_protocol_version,
                        'note': note
                    }
                }
                
                findings.append(finding)
        else:
            # No distributions found
            logger.info(f"No CloudFront distributions found in region {region}")
            
    except Exception as e:
        logger.error(f"Error in cloudfront_distributions_custom_ssl_certificate check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'CloudFront Distribution',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Use custom SSL certificates for CloudFront distributions'),
            'error': str(e)
        })
        
    return findings

def cloudfront_distributions_custom_ssl_certificate(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=cloudfront_distributions_custom_ssl_certificate_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = cloudfront_distributions_custom_ssl_certificate(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

#!/usr/bin/env python3
"""
pci_4.0_aws - cloudfront_distributions_https_sni_enabled

Checks if Amazon CloudFront distributions are using a custom SSL certificate and are configured to use SNI to serve HTTPS requests
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
                    'recommendation': entry.get('Recommendation', 'Configure CloudFront distributions to use SNI for HTTPS requests')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'pci_4.0_aws',
        'function_name': 'cloudfront_distributions_https_sni_enabled',
        'id': 'PCI-4.0-AWS-CF-SNI',
        'name': 'CloudFront Distributions HTTPS SNI Enabled',
        'description': 'Checks if Amazon CloudFront distributions are using a custom SSL certificate and are configured to use SNI to serve HTTPS requests',
        'api_function': 'client = boto3.client(\'cloudfront\')',
        'user_function': 'list_distributions(), get_distribution_config()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Configure CloudFront distributions to use SNI for HTTPS requests'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('cloudfront_distributions_https_sni_enabled')

def cloudfront_distributions_https_sni_enabled_check(cloudfront_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Check if CloudFront distributions use SNI for HTTPS requests.
    
    Args:
        cloudfront_client: Boto3 CloudFront client
        region (str): AWS region
        profile (str): AWS profile name
        logger: Logger instance
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    try:
        # List all CloudFront distributions
        response = cloudfront_client.list_distributions()
        distributions = response.get('DistributionList', {}).get('Items', [])
        
        if not distributions:
            # No distributions found - compliant (nothing to check)
            findings.append({
                'region': 'global',  # CloudFront is global
                'profile': profile,
                'resource_type': 'CloudFront Distributions',
                'resource_id': 'cloudfront-distributions-global',
                'status': 'COMPLIANT',
                'compliance_status': 'PASS',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                'recommendation': 'No CloudFront distributions found',
                'details': {
                    'distribution_count': 0,
                    'reason': 'No distributions to evaluate'
                }
            })
        else:
            # Check each distribution
            for distribution in distributions:
                distribution_id = distribution.get('Id', 'Unknown')
                domain_name = distribution.get('DomainName', 'Unknown')
                status = distribution.get('Status', 'Unknown')
                
                try:
                    # Get detailed distribution configuration
                    config_response = cloudfront_client.get_distribution_config(Id=distribution_id)
                    distribution_config = config_response.get('DistributionConfig', {})
                    
                    # Check viewer certificate configuration
                    viewer_certificate = distribution_config.get('ViewerCertificate', {})
                    ssl_support_method = viewer_certificate.get('SSLSupportMethod')
                    certificate_source = viewer_certificate.get('CertificateSource')
                    acm_certificate_arn = viewer_certificate.get('ACMCertificateArn')
                    iam_certificate_id = viewer_certificate.get('IAMCertificateId')
                    
                    # Check if using custom SSL certificate with SNI
                    is_using_custom_cert = bool(acm_certificate_arn or iam_certificate_id)
                    is_using_sni = ssl_support_method == 'sni-only'
                    
                    if is_using_custom_cert and is_using_sni:
                        # Distribution uses custom certificate with SNI - compliant
                        findings.append({
                            'region': 'global',
                            'profile': profile,
                            'resource_type': 'CloudFront Distribution',
                            'resource_id': distribution_id,
                            'status': 'COMPLIANT',
                            'compliance_status': 'PASS',
                            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                            'recommendation': 'CloudFront distribution properly configured with SNI',
                            'details': {
                                'distribution_id': distribution_id,
                                'domain_name': domain_name,
                                'status': status,
                                'ssl_support_method': ssl_support_method,
                                'certificate_source': certificate_source,
                                'custom_certificate': is_using_custom_cert,
                                'sni_enabled': is_using_sni
                            }
                        })
                    elif is_using_custom_cert and not is_using_sni:
                        # Distribution uses custom certificate but not SNI - non-compliant
                        findings.append({
                            'region': 'global',
                            'profile': profile,
                            'resource_type': 'CloudFront Distribution',
                            'resource_id': distribution_id,
                            'status': 'NON_COMPLIANT',
                            'compliance_status': 'FAIL',
                            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Configure CloudFront distributions to use SNI for HTTPS requests'),
                            'details': {
                                'distribution_id': distribution_id,
                                'domain_name': domain_name,
                                'status': status,
                                'ssl_support_method': ssl_support_method,
                                'certificate_source': certificate_source,
                                'custom_certificate': is_using_custom_cert,
                                'sni_enabled': is_using_sni,
                                'issue': 'Custom SSL certificate is used but SNI is not enabled'
                            }
                        })
                    elif not is_using_custom_cert:
                        # Distribution uses default CloudFront certificate - compliant for this check
                        findings.append({
                            'region': 'global',
                            'profile': profile,
                            'resource_type': 'CloudFront Distribution',
                            'resource_id': distribution_id,
                            'status': 'COMPLIANT',
                            'compliance_status': 'PASS',
                            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                            'recommendation': 'Distribution uses default CloudFront certificate',
                            'details': {
                                'distribution_id': distribution_id,
                                'domain_name': domain_name,
                                'status': status,
                                'ssl_support_method': ssl_support_method or 'default',
                                'certificate_source': certificate_source or 'cloudfront',
                                'custom_certificate': is_using_custom_cert,
                                'sni_enabled': 'N/A (default certificate)',
                                'note': 'Using default CloudFront certificate - SNI check not applicable'
                            }
                        })
                    
                except Exception as e:
                    logger.warning(f"Error getting configuration for distribution {distribution_id}: {e}")
                    findings.append({
                        'region': 'global',
                        'profile': profile,
                        'resource_type': 'CloudFront Distribution',
                        'resource_id': distribution_id,
                        'status': 'ERROR',
                        'compliance_status': 'ERROR',
                        'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                        'recommendation': COMPLIANCE_DATA.get('recommendation', 'Configure CloudFront distributions to use SNI for HTTPS requests'),
                        'details': {
                            'distribution_id': distribution_id,
                            'domain_name': domain_name,
                            'error': f'Error getting distribution configuration: {str(e)}'
                        }
                    })
            
            # Add summary finding
            compliant_distributions = sum(1 for finding in findings if finding.get('status') == 'COMPLIANT')
            
            findings.append({
                'region': 'global',
                'profile': profile,
                'resource_type': 'CloudFront Summary',
                'resource_id': 'cloudfront-sni-summary-global',
                'status': 'COMPLIANT' if compliant_distributions == len(distributions) else 'NON_COMPLIANT',
                'compliance_status': 'PASS' if compliant_distributions == len(distributions) else 'FAIL',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                'recommendation': 'All CloudFront distributions properly configured' if compliant_distributions == len(distributions) else COMPLIANCE_DATA.get('recommendation', 'Configure CloudFront distributions to use SNI for HTTPS requests'),
                'details': {
                    'total_distributions': len(distributions),
                    'compliant_distributions': compliant_distributions,
                    'non_compliant_distributions': len(distributions) - compliant_distributions,
                    'compliance_percentage': round((compliant_distributions / len(distributions)) * 100, 2) if distributions else 0
                }
            })
        
    except Exception as e:
        logger.error(f"Error in cloudfront_distributions_https_sni_enabled check: {e}")
        findings.append({
            'region': 'global',
            'profile': profile,
            'resource_type': 'CloudFront Distributions',
            'resource_id': 'cloudfront-sni-check-global',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Configure CloudFront distributions to use SNI for HTTPS requests'),
            'error': str(e)
        })
        
    return findings

def cloudfront_distributions_https_sni_enabled(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=cloudfront_distributions_https_sni_enabled_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = cloudfront_distributions_https_sni_enabled(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

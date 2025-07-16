#!/usr/bin/env python3
"""
aws_foundational_security_best_practices_aws - cloudfront_distributions_origin_traffic_encrypted

This control checks if Amazon CloudFront distributions are encrypting traffic to custom origins. This control fails for a CloudFront distribution whose origin protocol policy allows 'http-only'. This control also fails if the distribution's origin protocol policy is 'match-viewer' while the viewer protocol policy is 'allow-all'.
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
                    'risk_level': entry.get('Risk Level', 'MEDIUM'),
                    'recommendation': entry.get('Recommendation', 'Enable HTTPS-only origin protocol policy for CloudFront distributions')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'aws_foundational_security_best_practices_aws',
        'function_name': 'cloudfront_distributions_origin_traffic_encrypted',
        'id': 'CloudFront.9',
        'name': 'CloudFront distributions should encrypt traffic to custom origins',
        'description': 'This control checks if Amazon CloudFront distributions are encrypting traffic to custom origins.',
        'api_function': 'client = boto3.client(\'cloudfront\')',
        'user_function': 'list_distributions(), get_distribution_config()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Enable HTTPS-only origin protocol policy for CloudFront distributions'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('cloudfront_distributions_origin_traffic_encrypted')

def cloudfront_distributions_origin_traffic_encrypted_check(cloudfront_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for cloudfront_distributions_origin_traffic_encrypted.
    
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
        distributions_response = cloudfront_client.list_distributions()
        
        if 'DistributionList' not in distributions_response or 'Items' not in distributions_response['DistributionList']:
            logger.info("No CloudFront distributions found")
            return findings
            
        distributions = distributions_response['DistributionList']['Items']
        
        for distribution in distributions:
            distribution_id = distribution.get('Id')
            domain_name = distribution.get('DomainName', 'Unknown')
            
            try:
                # Get detailed distribution configuration
                config_response = cloudfront_client.get_distribution_config(Id=distribution_id)
                distribution_config = config_response['DistributionConfig']
                
                # Check origins for encryption compliance
                origins = distribution_config.get('Origins', {}).get('Items', [])
                viewer_protocol_policy = distribution_config.get('DefaultCacheBehavior', {}).get('ViewerProtocolPolicy', '')
                
                is_compliant = True
                non_compliant_origins = []
                
                for origin in origins:
                    origin_id = origin.get('Id', 'Unknown')
                    
                    # Check if this is a custom origin (not S3)
                    if 'CustomOriginConfig' in origin:
                        custom_config = origin['CustomOriginConfig']
                        origin_protocol_policy = custom_config.get('OriginProtocolPolicy', '')
                        
                        # Check for non-compliant configurations
                        if origin_protocol_policy == 'http-only':
                            is_compliant = False
                            non_compliant_origins.append({
                                'origin_id': origin_id,
                                'reason': 'Origin protocol policy is http-only'
                            })
                        elif origin_protocol_policy == 'match-viewer' and viewer_protocol_policy == 'allow-all':
                            is_compliant = False
                            non_compliant_origins.append({
                                'origin_id': origin_id,
                                'reason': 'Origin protocol policy is match-viewer while viewer protocol policy is allow-all'
                            })
                
                # Create finding
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'CloudFront Distribution',
                    'resource_id': distribution_id,
                    'status': 'COMPLIANT' if is_compliant else 'NON_COMPLIANT',
                    'compliance_status': 'PASS' if is_compliant else 'FAIL',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable HTTPS-only origin protocol policy'),
                    'details': {
                        'distribution_id': distribution_id,
                        'domain_name': domain_name,
                        'viewer_protocol_policy': viewer_protocol_policy,
                        'total_origins': len(origins),
                        'non_compliant_origins': non_compliant_origins if not is_compliant else [],
                        'compliance_reason': 'All custom origins use encrypted traffic' if is_compliant else f'Found {len(non_compliant_origins)} non-compliant origins'
                    }
                }
                
                findings.append(finding)
                
            except Exception as e:
                logger.error(f"Error checking distribution {distribution_id}: {e}")
                findings.append({
                    'region': region,
                    'profile': profile,
                    'resource_type': 'CloudFront Distribution',
                    'resource_id': distribution_id,
                    'status': 'ERROR',
                    'compliance_status': 'ERROR',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable HTTPS-only origin protocol policy'),
                    'error': str(e)
                })
        
    except Exception as e:
        logger.error(f"Error in cloudfront_distributions_origin_traffic_encrypted check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'CloudFront Distribution',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable HTTPS-only origin protocol policy'),
            'error': str(e)
        })
        
    return findings

def cloudfront_distributions_origin_traffic_encrypted(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=cloudfront_distributions_origin_traffic_encrypted_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = cloudfront_distributions_origin_traffic_encrypted(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

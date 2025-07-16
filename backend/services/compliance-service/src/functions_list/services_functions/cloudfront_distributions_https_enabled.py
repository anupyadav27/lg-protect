#!/usr/bin/env python3
"""
aws_foundational_security_best_practices_aws - cloudfront_distributions_https_enabled

CloudFront distributions should require HTTPS
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
                    'recommendation': entry.get('Recommendation', 'Configure CloudFront distributions to require HTTPS')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'aws_foundational_security_best_practices_aws',
        'function_name': 'cloudfront_distributions_https_enabled',
        'id': 'CloudFront.3',
        'name': 'CloudFront distributions should require HTTPS',
        'description': 'This control checks whether CloudFront distributions are configured to require HTTPS.',
        'api_function': 'client = boto3.client(\'cloudfront\')',
        'user_function': 'list_distributions(), get_distribution_config()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Configure CloudFront distributions to require HTTPS'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('cloudfront_distributions_https_enabled')

def cloudfront_distributions_https_enabled_check(cloudfront_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for cloudfront_distributions_https_enabled.
    
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
                
                # Check default cache behavior viewer protocol policy
                default_cache_behavior = distribution_config.get('DefaultCacheBehavior', {})
                viewer_protocol_policy = default_cache_behavior.get('ViewerProtocolPolicy', 'allow-all')
                
                # Check additional cache behaviors
                cache_behaviors = distribution_config.get('CacheBehaviors', {}).get('Items', [])
                non_compliant_behaviors = []
                
                # Check if default behavior requires HTTPS
                https_required = viewer_protocol_policy in ['https-only', 'redirect-to-https']
                
                # Check additional cache behaviors
                for behavior in cache_behaviors:
                    behavior_policy = behavior.get('ViewerProtocolPolicy', 'allow-all')
                    if behavior_policy not in ['https-only', 'redirect-to-https']:
                        non_compliant_behaviors.append({
                            'path_pattern': behavior.get('PathPattern'),
                            'viewer_protocol_policy': behavior_policy
                        })
                
                # Determine overall compliance
                if https_required and len(non_compliant_behaviors) == 0:
                    status = 'COMPLIANT'
                    compliance_status = 'PASS'
                else:
                    status = 'NON_COMPLIANT'
                    compliance_status = 'FAIL'
                
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'CloudFront Distribution',
                    'resource_id': distribution_id,
                    'status': status,
                    'compliance_status': compliance_status,
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Configure CloudFront distributions to require HTTPS'),
                    'details': {
                        'distribution_id': distribution_id,
                        'domain_name': domain_name,
                        'default_viewer_protocol_policy': viewer_protocol_policy,
                        'https_required_for_default': https_required,
                        'total_cache_behaviors': len(cache_behaviors),
                        'non_compliant_behaviors_count': len(non_compliant_behaviors),
                        'non_compliant_behaviors': non_compliant_behaviors[:5],  # Limit to first 5
                        'distribution_enabled': distribution.get('Enabled', False)
                    }
                }
                
                findings.append(finding)
        else:
            # No distributions found
            logger.info(f"No CloudFront distributions found in region {region}")
            
    except Exception as e:
        logger.error(f"Error in cloudfront_distributions_https_enabled check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'CloudFront Distribution',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Configure CloudFront distributions to require HTTPS'),
            'error': str(e)
        })
        
    return findings

def cloudfront_distributions_https_enabled(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=cloudfront_distributions_https_enabled_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = cloudfront_distributions_https_enabled(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

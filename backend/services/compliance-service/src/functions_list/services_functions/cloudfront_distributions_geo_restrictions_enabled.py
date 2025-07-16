#!/usr/bin/env python3
"""
aws_foundational_security_best_practices_aws - cloudfront_distributions_geo_restrictions_enabled

CloudFront distributions should have geo restrictions enabled when appropriate
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
                    'risk_level': entry.get('Risk Level', 'LOW'),
                    'recommendation': entry.get('Recommendation', 'Configure geo restrictions on CloudFront distributions when required')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'aws_foundational_security_best_practices_aws',
        'function_name': 'cloudfront_distributions_geo_restrictions_enabled',
        'id': 'CloudFront.10',
        'name': 'CloudFront distributions should have geo restrictions configured',
        'description': 'This control checks whether CloudFront distributions have geo restrictions configured.',
        'api_function': 'client = boto3.client(\'cloudfront\')',
        'user_function': 'list_distributions(), get_distribution_config()',
        'risk_level': 'LOW',
        'recommendation': 'Configure geo restrictions on CloudFront distributions when required'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('cloudfront_distributions_geo_restrictions_enabled')

def cloudfront_distributions_geo_restrictions_enabled_check(cloudfront_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for cloudfront_distributions_geo_restrictions_enabled.
    
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
                
                # Check geo restriction configuration
                geo_restriction = distribution_config.get('Restrictions', {}).get('GeoRestriction', {})
                restriction_type = geo_restriction.get('RestrictionType', 'none')
                locations = geo_restriction.get('Items', [])
                quantity = geo_restriction.get('Quantity', 0)
                
                # Check if geo restrictions are configured
                geo_restrictions_enabled = restriction_type in ['whitelist', 'blacklist'] and quantity > 0
                
                # For this compliance check, we consider it compliant if:
                # 1. No geo restrictions (none) - acceptable for global distributions
                # 2. Geo restrictions are properly configured with locations
                if restriction_type == 'none':
                    status = 'COMPLIANT'
                    compliance_status = 'PASS'
                    note = 'No geo restrictions configured - acceptable for global access'
                elif geo_restrictions_enabled:
                    status = 'COMPLIANT'
                    compliance_status = 'PASS'
                    note = f'Geo restrictions properly configured with {quantity} locations'
                else:
                    status = 'NON_COMPLIANT'
                    compliance_status = 'FAIL'
                    note = 'Geo restrictions configured but no locations specified'
                
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'CloudFront Distribution',
                    'resource_id': distribution_id,
                    'status': status,
                    'compliance_status': compliance_status,
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'LOW'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Configure geo restrictions on CloudFront distributions when required'),
                    'details': {
                        'distribution_id': distribution_id,
                        'domain_name': domain_name,
                        'restriction_type': restriction_type,
                        'locations_count': quantity,
                        'locations': locations[:10],  # Limit to first 10 locations
                        'geo_restrictions_enabled': geo_restrictions_enabled,
                        'note': note,
                        'distribution_enabled': distribution.get('Enabled', False)
                    }
                }
                
                findings.append(finding)
        else:
            # No distributions found
            logger.info(f"No CloudFront distributions found in region {region}")
            
    except Exception as e:
        logger.error(f"Error in cloudfront_distributions_geo_restrictions_enabled check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'CloudFront Distribution',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'LOW'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Configure geo restrictions on CloudFront distributions when required'),
            'error': str(e)
        })
        
    return findings

def cloudfront_distributions_geo_restrictions_enabled(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=cloudfront_distributions_geo_restrictions_enabled_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = cloudfront_distributions_geo_restrictions_enabled(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

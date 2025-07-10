#!/usr/bin/env python3
"""
aws_foundational_security_best_practices_aws - cloudfront_distributions_with_geo_restrictions_enabled

CloudFront distributions should have geo-restriction enabled
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
        compliance_json_path = os.path.join(
            os.path.dirname(__file__), '..', '..', 'compliance_checks.json'
        )
        
        with open(compliance_json_path, 'r') as f:
            compliance_data = json.load(f)
        
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
        
    return {
        'compliance_name': 'aws_foundational_security_best_practices_aws',
        'function_name': 'cloudfront_distributions_with_geo_restrictions_enabled',
        'id': 'CloudFront.6',
        'name': 'CloudFront distributions should have geo-restriction enabled',
        'description': 'CloudFront distributions should have geo-restriction enabled',
        'api_function': 'client = boto3.client(\'cloudfront\')',
        'user_function': 'list_distributions(), get_distribution()',
        'risk_level': 'LOW',
        'recommendation': 'Enable geo-restrictions on CloudFront distributions as needed'
    }

COMPLIANCE_DATA = load_compliance_metadata('cloudfront_distributions_with_geo_restrictions_enabled')

def cloudfront_distributions_with_geo_restrictions_enabled_check(cloudfront_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for cloudfront_distributions_with_geo_restrictions_enabled.
    """
    findings = []
    
    try:
        # Get all CloudFront distributions
        paginator = cloudfront_client.get_paginator('list_distributions')
        distributions = []
        
        for page in paginator.paginate():
            distribution_list = page.get('DistributionList', {})
            distributions.extend(distribution_list.get('Items', []))
        
        if not distributions:
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'CloudFront Distribution',
                'resource_id': f'no-distributions-{region}',
                'status': 'COMPLIANT',
                'compliance_status': 'PASS',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'LOW'),
                'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable geo-restrictions on CloudFront distributions'),
                'details': {
                    'message': 'No CloudFront distributions found',
                    'distribution_count': 0
                }
            }
            findings.append(finding)
            return findings
        
        # Check each distribution for geo-restrictions
        for distribution in distributions:
            distribution_id = distribution.get('Id')
            domain_name = distribution.get('DomainName')
            distribution_arn = distribution.get('ARN')
            
            try:
                # Get detailed distribution configuration
                distribution_config_response = cloudfront_client.get_distribution(Id=distribution_id)
                distribution_config = distribution_config_response.get('Distribution', {}).get('DistributionConfig', {})
                
                # Check geo-restriction configuration
                restrictions = distribution_config.get('Restrictions', {})
                geo_restriction = restrictions.get('GeoRestriction', {})
                restriction_type = geo_restriction.get('RestrictionType', 'none')
                locations = geo_restriction.get('Items', [])
                
                # Determine if geo-restrictions are enabled
                if restriction_type in ['whitelist', 'blacklist'] and locations:
                    status = 'COMPLIANT'
                    compliance_status = 'PASS'
                    message = f'CloudFront distribution {distribution_id} has geo-restrictions enabled'
                else:
                    status = 'NON_COMPLIANT'
                    compliance_status = 'FAIL'
                    message = f'CloudFront distribution {distribution_id} does not have geo-restrictions enabled'
                
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'CloudFront Distribution',
                    'resource_id': distribution_arn or distribution_id,
                    'status': status,
                    'compliance_status': compliance_status,
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'LOW'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable geo-restrictions on CloudFront distributions'),
                    'details': {
                        'distribution_id': distribution_id,
                        'domain_name': domain_name,
                        'distribution_arn': distribution_arn,
                        'restriction_type': restriction_type,
                        'restricted_locations': locations,
                        'location_count': len(locations),
                        'enabled': distribution_config.get('Enabled', False),
                        'price_class': distribution_config.get('PriceClass'),
                        'message': message
                    }
                }
                findings.append(finding)
                
            except Exception as e:
                logger.error(f"Error checking distribution {distribution_id}: {e}")
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'CloudFront Distribution',
                    'resource_id': distribution_arn or distribution_id,
                    'status': 'ERROR',
                    'compliance_status': 'ERROR',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'LOW'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable geo-restrictions on CloudFront distributions'),
                    'error': str(e),
                    'details': {
                        'distribution_id': distribution_id,
                        'domain_name': domain_name,
                        'message': f'Error checking distribution {distribution_id}'
                    }
                }
                findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in cloudfront_distributions_with_geo_restrictions_enabled check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'CloudFront Distribution',
            'resource_id': f'error-{region}',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'LOW'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable geo-restrictions on CloudFront distributions'),
            'error': str(e)
        })
        
    return findings

def cloudfront_distributions_with_geo_restrictions_enabled(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=cloudfront_distributions_with_geo_restrictions_enabled_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    args = setup_command_line_interface(COMPLIANCE_DATA)
    results = cloudfront_distributions_with_geo_restrictions_enabled(
        profile_name=args.profile,
        region_name=args.region
    )
    save_results(results, args.output, args.verbose)
    exit_with_status(results)
#!/usr/bin/env python3
"""
aws_foundational_security_best_practices_aws - cloudfront_distributions_multiple_origin_failover_configured

CloudFront distributions should have origin failover configured
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
                    'recommendation': entry.get('Recommendation', 'Review and remediate as needed')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'aws_foundational_security_best_practices_aws',
        'function_name': 'cloudfront_distributions_multiple_origin_failover_configured',
        'id': 'CloudFront.4',
        'name': 'CloudFront distributions should have origin failover configured',
        'description': 'This control checks whether an Amazon CloudFront distribution is configured with an origin group that has two or more origins.',
        'api_function': 'client = boto3.client("cloudfront")',
        'user_function': 'get_distribution_config()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Configure origin failover with multiple origins for CloudFront distributions'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('cloudfront_distributions_multiple_origin_failover_configured')

def cloudfront_distributions_multiple_origin_failover_configured_check(cloudfront_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for cloudfront_distributions_multiple_origin_failover_configured.
    
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
        
        if 'DistributionList' not in response or 'Items' not in response['DistributionList']:
            return findings
            
        distributions = response['DistributionList']['Items']
        
        for distribution in distributions:
            distribution_id = distribution['Id']
            domain_name = distribution['DomainName']
            
            # Get detailed distribution configuration
            config_response = cloudfront_client.get_distribution_config(Id=distribution_id)
            config = config_response['DistributionConfig']
            
            # Check for origin groups (failover configuration)
            origin_groups = config.get('OriginGroups', {}).get('Items', [])
            has_origin_groups = len(origin_groups) > 0
            
            # Check if any origin group has multiple origins
            has_failover_configured = False
            origin_group_details = []
            
            for origin_group in origin_groups:
                members = origin_group.get('Members', {}).get('Items', [])
                if len(members) >= 2:
                    has_failover_configured = True
                    origin_group_details.append({
                        'origin_group_id': origin_group.get('Id', ''),
                        'member_count': len(members),
                        'primary_origin': members[0].get('OriginId', '') if members else '',
                        'secondary_origin': members[1].get('OriginId', '') if len(members) > 1 else ''
                    })
            
            status = 'COMPLIANT' if has_failover_configured else 'NON_COMPLIANT'
            compliance_status = 'PASS' if has_failover_configured else 'FAIL'
            
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'CloudFront Distribution',
                'resource_id': distribution_id,
                'status': status,
                'compliance_status': compliance_status,
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                'recommendation': COMPLIANCE_DATA.get('recommendation', 'Configure origin failover with multiple origins for CloudFront distributions'),
                'details': {
                    'distribution_id': distribution_id,
                    'distribution_domain': domain_name,
                    'has_origin_groups': has_origin_groups,
                    'has_failover_configured': has_failover_configured,
                    'origin_groups_count': len(origin_groups),
                    'origin_group_details': origin_group_details,
                    'total_origins': len(config.get('Origins', {}).get('Items', []))
                }
            }
            
            findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in cloudfront_distributions_multiple_origin_failover_configured check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'CloudFront Distribution',
            'status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Configure origin failover with multiple origins for CloudFront distributions'),
            'error': str(e)
        })
        
    return findings

def cloudfront_distributions_multiple_origin_failover_configured(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=cloudfront_distributions_multiple_origin_failover_configured_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = cloudfront_distributions_multiple_origin_failover_configured(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

#!/usr/bin/env python3
"""
aws_foundational_security_best_practices_aws - cloudfront_distributions_s3_origin_access_control

CloudFront distributions should use origin access control
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
        'function_name': 'cloudfront_distributions_s3_origin_access_control',
        'id': 'CloudFront.13',
        'name': 'CloudFront distributions should use origin access control',
        'description': 'This control checks whether an Amazon CloudFront distribution with an Amazon S3 origin has origin access control (OAC) configured.',
        'api_function': 'cloudfront_client = boto3.client("cloudfront"), s3_client = boto3.client("s3")',
        'user_function': 'list_distributions(), get_distribution_config(), head_bucket()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Configure origin access control (OAC) for CloudFront distributions with S3 origins'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('cloudfront_distributions_s3_origin_access_control')

def cloudfront_distributions_s3_origin_access_control_check(cloudfront_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for cloudfront_distributions_s3_origin_access_control.
    
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
            
            # Check each origin
            for origin in config.get('Origins', {}).get('Items', []):
                origin_id = origin['Id']
                domain_name_origin = origin['DomainName']
                
                # Check if this is an S3 origin (domain contains amazonaws.com or s3)
                is_s3_origin = (
                    '.amazonaws.com' in domain_name_origin.lower() or
                    's3' in domain_name_origin.lower() or
                    '.s3.' in domain_name_origin.lower()
                )
                
                if is_s3_origin:
                    # Check if Origin Access Control (OAC) is configured
                    has_oac = 'OriginAccessControlId' in origin and origin['OriginAccessControlId']
                    
                    # Check for legacy Origin Access Identity (OAI) - should be migrated to OAC
                    s3_origin_config = origin.get('S3OriginConfig', {})
                    has_oai = s3_origin_config.get('OriginAccessIdentity', '') != ''
                    
                    status = 'COMPLIANT' if has_oac else 'NON_COMPLIANT'
                    compliance_status = 'PASS' if has_oac else 'FAIL'
                    
                    finding = {
                        'region': region,
                        'profile': profile,
                        'resource_type': 'CloudFront Distribution',
                        'resource_id': distribution_id,
                        'status': status,
                        'compliance_status': compliance_status,
                        'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                        'recommendation': COMPLIANCE_DATA.get('recommendation', 'Configure origin access control (OAC) for CloudFront distributions with S3 origins'),
                        'details': {
                            'distribution_id': distribution_id,
                            'distribution_domain': domain_name,
                            'origin_id': origin_id,
                            'origin_domain': domain_name_origin,
                            'has_origin_access_control': has_oac,
                            'has_legacy_oai': has_oai,
                            'origin_access_control_id': origin.get('OriginAccessControlId', ''),
                            'note': 'OAC (Origin Access Control) is the recommended method over legacy OAI (Origin Access Identity)'
                        }
                    }
                    
                    findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in cloudfront_distributions_s3_origin_access_control check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'CloudFront Distribution',
            'status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Configure origin access control (OAC) for CloudFront distributions with S3 origins'),
            'error': str(e)
        })
        
    return findings

def cloudfront_distributions_s3_origin_access_control(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=cloudfront_distributions_s3_origin_access_control_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = cloudfront_distributions_s3_origin_access_control(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

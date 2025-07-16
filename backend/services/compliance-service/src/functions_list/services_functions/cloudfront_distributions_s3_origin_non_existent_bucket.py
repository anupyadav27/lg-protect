#!/usr/bin/env python3
"""
aws_foundational_security_best_practices_aws - cloudfront_distributions_s3_origin_non_existent_bucket

CloudFront distributions should not point to non-existent S3 origins
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
                    'recommendation': entry.get('Recommendation', 'Update CloudFront distributions to point to existing S3 buckets')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'aws_foundational_security_best_practices_aws',
        'function_name': 'cloudfront_distributions_s3_origin_non_existent_bucket',
        'id': 'FSBP-CF-S3-EXISTS',
        'name': 'CloudFront S3 Origin Bucket Exists',
        'description': 'CloudFront distributions should not point to non-existent S3 origins',
        'api_function': 'client = boto3.client(\'cloudfront\'), client = boto3.client(\'s3\')',
        'user_function': 'list_distributions(), get_distribution_config(), head_bucket()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Update CloudFront distributions to point to existing S3 buckets'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('cloudfront_distributions_s3_origin_non_existent_bucket')

def cloudfront_distributions_s3_origin_non_existent_bucket_check(cloudfront_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Check if CloudFront distributions point to non-existent S3 buckets.
    
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
        # Create S3 client to check bucket existence
        import boto3
        s3_client = boto3.client('s3')
        
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
                    
                    # Check origins for S3 buckets
                    origins = distribution_config.get('Origins', {}).get('Items', [])
                    s3_origins = []
                    non_existent_buckets = []
                    
                    for origin in origins:
                        origin_id = origin.get('Id', 'Unknown')
                        domain_name_origin = origin.get('DomainName', '')
                        
                        # Check if this is an S3 origin
                        if '.s3.' in domain_name_origin or '.s3-' in domain_name_origin or domain_name_origin.endswith('.s3.amazonaws.com'):
                            # Extract bucket name from domain
                            if domain_name_origin.endswith('.s3.amazonaws.com'):
                                bucket_name = domain_name_origin.replace('.s3.amazonaws.com', '')
                            else:
                                # Handle regional S3 endpoints
                                bucket_name = domain_name_origin.split('.s3.')[0]
                            
                            s3_origins.append({
                                'origin_id': origin_id,
                                'domain_name': domain_name_origin,
                                'bucket_name': bucket_name
                            })
                            
                            try:
                                # Check if bucket exists
                                s3_client.head_bucket(Bucket=bucket_name)
                                # Bucket exists - no action needed
                            except Exception as bucket_error:
                                if 'NoSuchBucket' in str(bucket_error) or '404' in str(bucket_error):
                                    non_existent_buckets.append({
                                        'origin_id': origin_id,
                                        'domain_name': domain_name_origin,
                                        'bucket_name': bucket_name,
                                        'error': 'Bucket does not exist'
                                    })
                                elif 'AccessDenied' in str(bucket_error) or '403' in str(bucket_error):
                                    # Access denied - bucket might exist but we can't access it
                                    # This is not necessarily a compliance issue
                                    pass
                                else:
                                    logger.warning(f"Error checking bucket {bucket_name}: {bucket_error}")
                    
                    if non_existent_buckets:
                        # Distribution has non-existent S3 origins - non-compliant
                        findings.append({
                            'region': 'global',
                            'profile': profile,
                            'resource_type': 'CloudFront Distribution',
                            'resource_id': distribution_id,
                            'status': 'NON_COMPLIANT',
                            'compliance_status': 'FAIL',
                            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Update CloudFront distributions to point to existing S3 buckets'),
                            'details': {
                                'distribution_id': distribution_id,
                                'domain_name': domain_name,
                                'status': status,
                                'total_origins': len(origins),
                                's3_origins_count': len(s3_origins),
                                'non_existent_buckets': non_existent_buckets,
                                'issue': f'{len(non_existent_buckets)} S3 origin(s) point to non-existent buckets'
                            }
                        })
                    elif s3_origins:
                        # Distribution has S3 origins and all exist - compliant
                        findings.append({
                            'region': 'global',
                            'profile': profile,
                            'resource_type': 'CloudFront Distribution',
                            'resource_id': distribution_id,
                            'status': 'COMPLIANT',
                            'compliance_status': 'PASS',
                            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                            'recommendation': 'All S3 origins point to existing buckets',
                            'details': {
                                'distribution_id': distribution_id,
                                'domain_name': domain_name,
                                'status': status,
                                'total_origins': len(origins),
                                's3_origins_count': len(s3_origins),
                                's3_origins': [origin['bucket_name'] for origin in s3_origins]
                            }
                        })
                    else:
                        # Distribution has no S3 origins - compliant for this check
                        findings.append({
                            'region': 'global',
                            'profile': profile,
                            'resource_type': 'CloudFront Distribution',
                            'resource_id': distribution_id,
                            'status': 'COMPLIANT',
                            'compliance_status': 'PASS',
                            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                            'recommendation': 'Distribution has no S3 origins',
                            'details': {
                                'distribution_id': distribution_id,
                                'domain_name': domain_name,
                                'status': status,
                                'total_origins': len(origins),
                                's3_origins_count': 0,
                                'note': 'No S3 origins to check'
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
                        'recommendation': COMPLIANCE_DATA.get('recommendation', 'Update CloudFront distributions to point to existing S3 buckets'),
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
                'resource_id': 'cloudfront-s3-origins-summary-global',
                'status': 'COMPLIANT' if compliant_distributions == len(distributions) else 'NON_COMPLIANT',
                'compliance_status': 'PASS' if compliant_distributions == len(distributions) else 'FAIL',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                'recommendation': 'All CloudFront distributions have valid S3 origins' if compliant_distributions == len(distributions) else COMPLIANCE_DATA.get('recommendation', 'Update CloudFront distributions to point to existing S3 buckets'),
                'details': {
                    'total_distributions': len(distributions),
                    'compliant_distributions': compliant_distributions,
                    'non_compliant_distributions': len(distributions) - compliant_distributions,
                    'compliance_percentage': round((compliant_distributions / len(distributions)) * 100, 2) if distributions else 0
                }
            })
        
    except Exception as e:
        logger.error(f"Error in cloudfront_distributions_s3_origin_non_existent_bucket check: {e}")
        findings.append({
            'region': 'global',
            'profile': profile,
            'resource_type': 'CloudFront Distributions',
            'resource_id': 'cloudfront-s3-origins-check-global',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Update CloudFront distributions to point to existing S3 buckets'),
            'error': str(e)
        })
        
    return findings

def cloudfront_distributions_s3_origin_non_existent_bucket(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=cloudfront_distributions_s3_origin_non_existent_bucket_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = cloudfront_distributions_s3_origin_non_existent_bucket(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

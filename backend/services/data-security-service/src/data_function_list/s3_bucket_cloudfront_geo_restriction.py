#!/usr/bin/env python3
"""
data_security_aws - s3_bucket_cloudfront_geo_restriction

Ensure S3 content served through CloudFront has appropriate geo-restrictions to comply with data residency and export control requirements.
"""

# Rule Metadata from YAML:
# Function Name: s3_bucket_cloudfront_geo_restriction
# Capability: DATA_RESIDENCY
# Service: S3
# Subservice: DISTRIBUTION
# Description: Ensure S3 content served through CloudFront has appropriate geo-restrictions to comply with data residency and export control requirements.
# Risk Level: MEDIUM
# Recommendation: Enforce CloudFront geo-restrictions for S3 content
# API Function: client = boto3.client('s3')
# User Function: s3_bucket_cloudfront_geo_restriction()

# Import required modules
import boto3
import json
import sys
from typing import Dict, List, Any
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def load_rule_metadata(function_name: str) -> Dict[str, Any]:
    """Load rule metadata from YAML configuration."""
    return {
        "function_name": "s3_bucket_cloudfront_geo_restriction",
        "title": "Enforce CloudFront geo-restrictions for S3 content",
        "description": "Ensure S3 content served through CloudFront has appropriate geo-restrictions to comply with data residency and export control requirements.",
        "capability": "data_residency",
        "service": "s3",
        "subservice": "distribution",
        "risk": "MEDIUM",
        "existing": False
    }

def s3_bucket_cloudfront_geo_restriction_check(region_name: str, profile_name: str = None) -> List[Dict[str, Any]]:
    """
    Check s3 resources for data_residency compliance.
    
    Args:
        region_name (str): AWS region name
        profile_name (str): AWS profile name (optional)
        
    Returns:
        List[Dict]: List of compliance findings
    """
    findings = []
    
    try:
        # Initialize boto3 clients
        session = boto3.Session(profile_name=profile_name)
        s3_client = session.client('s3', region_name=region_name)
        cloudfront_client = session.client('cloudfront')
        
        logger.info(f"Checking S3 resources for data_residency compliance in region {region_name}")
        
        # Get all S3 buckets
        response = s3_client.list_buckets()
        buckets = response.get('Buckets', [])
        
        # Get all CloudFront distributions
        cf_paginator = cloudfront_client.get_paginator('list_distributions')
        
        for bucket in buckets:
            bucket_name = bucket.get('Name')
            
            try:
                # Check bucket region to ensure we're only checking buckets in the specified region
                bucket_location = s3_client.get_bucket_location(Bucket=bucket_name)
                bucket_region = bucket_location.get('LocationConstraint') or 'us-east-1'
                
                # Only check buckets in the specified region
                if bucket_region != region_name:
                    continue
                
                # Find CloudFront distributions that serve this S3 bucket
                bucket_distributions = []
                
                for page in cf_paginator.paginate():
                    distributions = page.get('DistributionList', {}).get('Items', [])
                    
                    for distribution in distributions:
                        dist_id = distribution.get('Id')
                        dist_arn = distribution.get('ARN')
                        
                        # Check if this distribution serves our S3 bucket
                        origins = distribution.get('Origins', {}).get('Items', [])
                        
                        for origin in origins:
                            origin_domain = origin.get('DomainName', '')
                            
                            # Check if origin points to our S3 bucket
                            if bucket_name in origin_domain and 's3' in origin_domain:
                                # Get detailed distribution config to check geo restrictions
                                try:
                                    dist_config = cloudfront_client.get_distribution(Id=dist_id)
                                    config = dist_config.get('Distribution', {}).get('DistributionConfig', {})
                                    
                                    restrictions = config.get('Restrictions', {}).get('GeoRestriction', {})
                                    restriction_type = restrictions.get('RestrictionType', 'none')
                                    
                                    bucket_distributions.append({
                                        'id': dist_id,
                                        'arn': dist_arn,
                                        'domain_name': distribution.get('DomainName'),
                                        'status': distribution.get('Status'),
                                        'restriction_type': restriction_type,
                                        'restricted_locations': restrictions.get('Items', []),
                                        'restriction_count': restrictions.get('Quantity', 0)
                                    })
                                    
                                except Exception as dist_error:
                                    logger.warning(f"Failed to get distribution config for {dist_id}: {dist_error}")
                                
                                break
                
                # Analyze findings for this bucket
                if not bucket_distributions:
                    # Bucket not served through CloudFront - might be compliant or needs review
                    findings.append({
                        "region": region_name,
                        "profile": profile_name or "default",
                        "resource_type": "s3_bucket",
                        "resource_id": f"arn:aws:s3:::{bucket_name}",
                        "status": "COMPLIANT",
                        "risk_level": "MEDIUM",
                        "recommendation": "S3 bucket is not served through CloudFront",
                        "details": {
                            "bucket_name": bucket_name,
                            "bucket_region": bucket_region,
                            "cloudfront_distributions_count": 0,
                            "note": "No CloudFront distributions found serving this bucket"
                        }
                    })
                else:
                    # Check geo restrictions on distributions serving this bucket
                    compliant_distributions = 0
                    non_compliant_distributions = 0
                    
                    for dist in bucket_distributions:
                        if dist['restriction_type'] == 'none':
                            non_compliant_distributions += 1
                        else:
                            compliant_distributions += 1
                    
                    if non_compliant_distributions > 0:
                        findings.append({
                            "region": region_name,
                            "profile": profile_name or "default",
                            "resource_type": "s3_bucket",
                            "resource_id": f"arn:aws:s3:::{bucket_name}",
                            "status": "NON_COMPLIANT",
                            "risk_level": "MEDIUM",
                            "recommendation": "Configure geo-restrictions on CloudFront distributions serving S3 content",
                            "details": {
                                "bucket_name": bucket_name,
                                "bucket_region": bucket_region,
                                "violation": f"{non_compliant_distributions} distributions without geo-restrictions",
                                "cloudfront_distributions_count": len(bucket_distributions),
                                "compliant_distributions": compliant_distributions,
                                "non_compliant_distributions": non_compliant_distributions,
                                "distributions": bucket_distributions
                            }
                        })
                    else:
                        findings.append({
                            "region": region_name,
                            "profile": profile_name or "default",
                            "resource_type": "s3_bucket",
                            "resource_id": f"arn:aws:s3:::{bucket_name}",
                            "status": "COMPLIANT",
                            "risk_level": "MEDIUM",
                            "recommendation": "CloudFront distributions have appropriate geo-restrictions",
                            "details": {
                                "bucket_name": bucket_name,
                                "bucket_region": bucket_region,
                                "cloudfront_distributions_count": len(bucket_distributions),
                                "all_distributions_have_restrictions": True,
                                "distributions": bucket_distributions
                            }
                        })
                
            except Exception as bucket_error:
                logger.warning(f"Failed to check bucket {bucket_name}: {bucket_error}")
                findings.append({
                    "region": region_name,
                    "profile": profile_name or "default",
                    "resource_type": "s3_bucket",
                    "resource_id": f"arn:aws:s3:::{bucket_name}",
                    "status": "ERROR",
                    "risk_level": "MEDIUM",
                    "recommendation": "Unable to check CloudFront geo-restrictions",
                    "details": {
                        "bucket_name": bucket_name,
                        "error": str(bucket_error)
                    }
                })
        
        logger.info(f"Completed checking s3_bucket_cloudfront_geo_restriction. Found {len(findings)} findings.")
        
    except Exception as e:
        logger.error(f"Failed to check s3_bucket_cloudfront_geo_restriction: {e}")
        findings.append({
            "region": region_name,
            "profile": profile_name or "default",
            "resource_type": "s3_bucket",
            "resource_id": "unknown",
            "status": "ERROR",
            "risk_level": "MEDIUM",
            "recommendation": "Fix API access issues",
            "details": {
                "error": str(e)
            }
        })
    
    return findings

def s3_bucket_cloudfront_geo_restriction(region_name: str, profile_name: str = None) -> Dict[str, Any]:
    """
    Main function wrapper for s3_bucket_cloudfront_geo_restriction.
    
    Args:
        region_name (str): AWS region name
        profile_name (str): AWS profile name (optional)
        
    Returns:
        Dict: Results summary
    """
    COMPLIANCE_DATA = load_rule_metadata("s3_bucket_cloudfront_geo_restriction")
    
    # TODO: Implement SecurityEngine integration when available
    # from data_security_engine import SecurityEngine
    # engine = SecurityEngine(COMPLIANCE_DATA)
    # return engine.run_check(region_name, profile_name, s3_bucket_cloudfront_geo_restriction_check)
    
    # Current implementation
    findings = s3_bucket_cloudfront_geo_restriction_check(region_name, profile_name)
    
    # Calculate compliance statistics
    total_findings = len(findings)
    compliant_findings = len([f for f in findings if f['status'] == 'COMPLIANT'])
    non_compliant_findings = len([f for f in findings if f['status'] == 'NON_COMPLIANT'])
    error_findings = len([f for f in findings if f['status'] == 'ERROR'])
    
    return {
        "function_name": "s3_bucket_cloudfront_geo_restriction",
        "region": region_name,
        "profile": profile_name or "default",
        "total_findings": total_findings,
        "compliant_count": compliant_findings,
        "non_compliant_count": non_compliant_findings,
        "error_count": error_findings,
        "compliance_rate": (compliant_findings / total_findings * 100) if total_findings > 0 else 0,
        "findings": findings
    }

def main():
    """CLI entry point for s3_bucket_cloudfront_geo_restriction."""
    # TODO: Implement setup_command_line_interface() when data_security_engine is available
    # from data_security_engine import setup_command_line_interface, save_results, exit_with_status
    # args = setup_command_line_interface()
    # results = s3_bucket_cloudfront_geo_restriction(args.region, args.profile)
    # save_results(results, args.output_file)
    # exit_with_status(results)
    
    # Current CLI implementation
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Ensure S3 content served through CloudFront has appropriate geo-restrictions to comply with data residency and export control requirements."
    )
    parser.add_argument("--region", default="us-east-1", help="AWS region")
    parser.add_argument("--profile", help="AWS profile name")
    parser.add_argument("--output", help="Output file for results (JSON format)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        results = s3_bucket_cloudfront_geo_restriction(args.region, args.profile)
        
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"Results saved to {args.output}")
        else:
            print(json.dumps(results, indent=2))
            
        # Exit with appropriate code
        if results['error_count'] > 0:
            sys.exit(2)  # Errors encountered
        elif results['non_compliant_count'] > 0:
            sys.exit(1)  # Non-compliant resources found
        else:
            sys.exit(0)  # All compliant
            
    except Exception as e:
        logger.error(f"Execution failed: {e}")
        sys.exit(3)

if __name__ == "__main__":
    main()

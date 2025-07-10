#!/usr/bin/env python3
"""
data_security_aws - s3_bucket_region_restriction_enforced

Ensure S3 buckets are created only in approved regions to comply with data sovereignty and geographic data residency requirements.
"""

# Rule Metadata from YAML:
# Function Name: s3_bucket_region_restriction_enforced
# Capability: DATA_RESIDENCY
# Service: S3
# Subservice: REGION
# Description: Ensure S3 buckets are created only in approved regions to comply with data sovereignty and geographic data residency requirements.
# Risk Level: HIGH
# Recommendation: Enforce data residency through region restrictions
# API Function: client = boto3.client('s3')
# User Function: s3_bucket_region_restriction_enforced()

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
        "function_name": "s3_bucket_region_restriction_enforced",
        "title": "Enforce data residency through region restrictions",
        "description": "Ensure S3 buckets are created only in approved regions to comply with data sovereignty and geographic data residency requirements.",
        "capability": "data_residency",
        "service": "s3",
        "subservice": "region",
        "risk": "HIGH",
        "existing": False
    }

def s3_bucket_region_restriction_enforced_check(region_name: str, profile_name: str = None) -> List[Dict[str, Any]]:
    """
    Check S3 buckets for region restriction compliance.
    
    Args:
        region_name (str): AWS region name
        profile_name (str): AWS profile name (optional)
        
    Returns:
        List[Dict]: List of compliance findings
    """
    findings = []
    
    # Define approved regions for data residency compliance
    # This should be configurable based on organization's data sovereignty requirements
    APPROVED_REGIONS = {
        'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',  # US regions
        'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-central-1',  # EU regions
        'ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1'  # APAC regions
    }
    
    try:
        # Initialize boto3 client
        session = boto3.Session(profile_name=profile_name)
        s3_client = session.client('s3', region_name=region_name)
        
        logger.info(f"Checking S3 bucket region restrictions for data residency compliance in region {region_name}")
        
        # List all S3 buckets (this is a global operation)
        response = s3_client.list_buckets()
        buckets = response.get('Buckets', [])
        
        for bucket in buckets:
            bucket_name = bucket.get('Name')
            creation_date = bucket.get('CreationDate')
            
            try:
                # Get bucket location
                location_response = s3_client.get_bucket_location(Bucket=bucket_name)
                bucket_region = location_response.get('LocationConstraint')
                
                # Handle default region (us-east-1 returns None)
                if bucket_region is None:
                    bucket_region = 'us-east-1'
                
                # Check if bucket region is in approved list
                if bucket_region not in APPROVED_REGIONS:
                    findings.append({
                        "region": region_name,
                        "profile": profile_name or "default",
                        "resource_type": "s3_bucket",
                        "resource_id": f"arn:aws:s3:::{bucket_name}",
                        "status": "NON_COMPLIANT",
                        "risk_level": "HIGH",
                        "recommendation": "Move bucket to an approved region for data sovereignty compliance",
                        "details": {
                            "bucket_name": bucket_name,
                            "bucket_region": bucket_region,
                            "creation_date": creation_date.isoformat() if creation_date else None,
                            "violation": f"Bucket is located in non-approved region: {bucket_region}",
                            "approved_regions": list(APPROVED_REGIONS)
                        }
                    })
                else:
                    # Check for bucket policy that might allow cross-region access
                    try:
                        policy_response = s3_client.get_bucket_policy(Bucket=bucket_name)
                        bucket_policy = json.loads(policy_response.get('Policy', '{}'))
                        
                        # Analyze policy for cross-region access patterns
                        cross_region_risk = False
                        policy_warnings = []
                        
                        for statement in bucket_policy.get('Statement', []):
                            # Check for overly permissive principals
                            principal = statement.get('Principal')
                            if principal == '*' or (isinstance(principal, dict) and principal.get('AWS') == '*'):
                                cross_region_risk = True
                                policy_warnings.append("Policy allows access from any AWS account")
                            
                            # Check for condition-based region restrictions
                            conditions = statement.get('Condition', {})
                            string_equals = conditions.get('StringEquals', {})
                            string_not_equals = conditions.get('StringNotEquals', {})
                            
                            # Look for aws:RequestedRegion conditions
                            if 'aws:RequestedRegion' not in string_equals and 'aws:RequestedRegion' not in string_not_equals:
                                if statement.get('Effect') == 'Allow':
                                    policy_warnings.append("Policy does not restrict access by region")
                        
                        if cross_region_risk or policy_warnings:
                            findings.append({
                                "region": region_name,
                                "profile": profile_name or "default",
                                "resource_type": "s3_bucket",
                                "resource_id": f"arn:aws:s3:::{bucket_name}",
                                "status": "NON_COMPLIANT",
                                "risk_level": "MEDIUM",
                                "recommendation": "Review and restrict bucket policy to prevent cross-region data access",
                                "details": {
                                    "bucket_name": bucket_name,
                                    "bucket_region": bucket_region,
                                    "creation_date": creation_date.isoformat() if creation_date else None,
                                    "violation": "Bucket policy may allow cross-region access",
                                    "policy_warnings": policy_warnings
                                }
                            })
                        else:
                            findings.append({
                                "region": region_name,
                                "profile": profile_name or "default",
                                "resource_type": "s3_bucket",
                                "resource_id": f"arn:aws:s3:::{bucket_name}",
                                "status": "COMPLIANT",
                                "risk_level": "HIGH",
                                "recommendation": "Bucket is compliant with region restrictions",
                                "details": {
                                    "bucket_name": bucket_name,
                                    "bucket_region": bucket_region,
                                    "creation_date": creation_date.isoformat() if creation_date else None,
                                    "has_policy": True
                                }
                            })
                            
                    except s3_client.exceptions.NoSuchBucketPolicy:
                        # No bucket policy exists, which might be okay depending on use case
                        findings.append({
                            "region": region_name,
                            "profile": profile_name or "default",
                            "resource_type": "s3_bucket",
                            "resource_id": f"arn:aws:s3:::{bucket_name}",
                            "status": "COMPLIANT",
                            "risk_level": "HIGH",
                            "recommendation": "Consider adding bucket policy to explicitly restrict cross-region access",
                            "details": {
                                "bucket_name": bucket_name,
                                "bucket_region": bucket_region,
                                "creation_date": creation_date.isoformat() if creation_date else None,
                                "has_policy": False,
                                "note": "No bucket policy configured - relying on IAM controls"
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
                    "risk_level": "HIGH",
                    "recommendation": "Unable to check bucket region configuration",
                    "details": {
                        "bucket_name": bucket_name,
                        "error": str(bucket_error)
                    }
                })
        
        logger.info(f"Completed checking s3_bucket_region_restriction_enforced. Found {len(findings)} findings.")
        
    except Exception as e:
        logger.error(f"Failed to check s3_bucket_region_restriction_enforced: {e}")
        findings.append({
            "region": region_name,
            "profile": profile_name or "default",
            "resource_type": "s3_bucket",
            "resource_id": "unknown",
            "status": "ERROR",
            "risk_level": "HIGH",
            "recommendation": "Fix API access issues",
            "details": {
                "error": str(e)
            }
        })
    
    return findings

def s3_bucket_region_restriction_enforced(region_name: str, profile_name: str = None) -> Dict[str, Any]:
    """
    Main function wrapper for s3_bucket_region_restriction_enforced.
    
    Args:
        region_name (str): AWS region name
        profile_name (str): AWS profile name (optional)
        
    Returns:
        Dict: Results summary
    """
    COMPLIANCE_DATA = load_rule_metadata("s3_bucket_region_restriction_enforced")
    
    # TODO: Implement SecurityEngine integration when available
    # from data_security_engine import SecurityEngine
    # engine = SecurityEngine(COMPLIANCE_DATA)
    # return engine.run_check(region_name, profile_name, s3_bucket_region_restriction_enforced_check)
    
    # Current implementation
    findings = s3_bucket_region_restriction_enforced_check(region_name, profile_name)
    
    # Calculate compliance statistics
    total_findings = len(findings)
    compliant_findings = len([f for f in findings if f['status'] == 'COMPLIANT'])
    non_compliant_findings = len([f for f in findings if f['status'] == 'NON_COMPLIANT'])
    error_findings = len([f for f in findings if f['status'] == 'ERROR'])
    
    return {
        "function_name": "s3_bucket_region_restriction_enforced",
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
    """CLI entry point for s3_bucket_region_restriction_enforced."""
    # TODO: Implement setup_command_line_interface() when data_security_engine is available
    # from data_security_engine import setup_command_line_interface, save_results, exit_with_status
    # args = setup_command_line_interface()
    # results = s3_bucket_region_restriction_enforced(args.region, args.profile)
    # save_results(results, args.output_file)
    # exit_with_status(results)
    
    # Current CLI implementation
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Ensure S3 buckets are created only in approved regions to comply with data sovereignty and geographic data residency requirements."
    )
    parser.add_argument("--region", default="us-east-1", help="AWS region")
    parser.add_argument("--profile", help="AWS profile name")
    parser.add_argument("--output", help="Output file for results (JSON format)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        results = s3_bucket_region_restriction_enforced(args.region, args.profile)
        
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

#!/usr/bin/env python3
"""
data_security_aws - s3_bucket_intelligent_tiering_enabled

Configure S3 Intelligent Tiering to automatically optimize storage costs while maintaining data accessibility and compliance.
"""

# Rule Metadata from YAML:
# Function Name: s3_bucket_intelligent_tiering_enabled
# Capability: DATA_PROTECTION
# Service: S3
# Subservice: LIFECYCLE
# Description: Configure S3 Intelligent Tiering to automatically optimize storage costs while maintaining data accessibility and compliance.
# Risk Level: LOW
# Recommendation: Enable S3 Intelligent Tiering for cost optimization
# API Function: client = boto3.client('s3')
# User Function: s3_bucket_intelligent_tiering_enabled()

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
        "function_name": "s3_bucket_intelligent_tiering_enabled",
        "title": "Enable S3 Intelligent Tiering for cost optimization",
        "description": "Configure S3 Intelligent Tiering to automatically optimize storage costs while maintaining data accessibility and compliance.",
        "capability": "data_protection",
        "service": "s3",
        "subservice": "lifecycle",
        "risk": "LOW",
        "existing": False
    }

def s3_bucket_intelligent_tiering_enabled_check(region_name: str, profile_name: str = None) -> List[Dict[str, Any]]:
    """
    Check s3 resources for data_protection compliance.
    
    Args:
        region_name (str): AWS region name
        profile_name (str): AWS profile name (optional)
        
    Returns:
        List[Dict]: List of compliance findings
    """
    findings = []
    
    try:
        # Initialize boto3 client
        session = boto3.Session(profile_name=profile_name)
        s3_client = session.client('s3', region_name=region_name)
        
        logger.info(f"Checking S3 resources for data_protection compliance in region {region_name}")
        
        # Get all S3 buckets
        response = s3_client.list_buckets()
        buckets = response.get('Buckets', [])
        
        for bucket in buckets:
            bucket_name = bucket.get('Name')
            
            try:
                # Check bucket region to ensure we're only checking buckets in the specified region
                bucket_location = s3_client.get_bucket_location(Bucket=bucket_name)
                bucket_region = bucket_location.get('LocationConstraint') or 'us-east-1'
                
                # Only check buckets in the specified region
                if bucket_region != region_name:
                    continue
                
                # Check if Intelligent Tiering is configured for the bucket
                try:
                    intelligent_tiering_response = s3_client.list_bucket_intelligent_tiering_configurations(
                        Bucket=bucket_name
                    )
                    
                    intelligent_tiering_configs = intelligent_tiering_response.get('IntelligentTieringConfigurationList', [])
                    
                    if not intelligent_tiering_configs:
                        # No Intelligent Tiering configured
                        findings.append({
                            "region": region_name,
                            "profile": profile_name or "default",
                            "resource_type": "s3_bucket",
                            "resource_id": f"arn:aws:s3:::{bucket_name}",
                            "status": "NON_COMPLIANT",
                            "risk_level": "LOW",
                            "recommendation": "Enable S3 Intelligent Tiering for cost optimization",
                            "details": {
                                "bucket_name": bucket_name,
                                "bucket_region": bucket_region,
                                "violation": "No Intelligent Tiering configuration found",
                                "intelligent_tiering_configs_count": 0
                            }
                        })
                    else:
                        # Intelligent Tiering is configured
                        active_configs = [config for config in intelligent_tiering_configs 
                                        if config.get('Status') == 'Enabled']
                        
                        if active_configs:
                            findings.append({
                                "region": region_name,
                                "profile": profile_name or "default",
                                "resource_type": "s3_bucket",
                                "resource_id": f"arn:aws:s3:::{bucket_name}",
                                "status": "COMPLIANT",
                                "risk_level": "LOW",
                                "recommendation": "S3 Intelligent Tiering is properly configured",
                                "details": {
                                    "bucket_name": bucket_name,
                                    "bucket_region": bucket_region,
                                    "intelligent_tiering_configs_count": len(intelligent_tiering_configs),
                                    "active_configs_count": len(active_configs),
                                    "config_ids": [config.get('Id') for config in active_configs]
                                }
                            })
                        else:
                            findings.append({
                                "region": region_name,
                                "profile": profile_name or "default",
                                "resource_type": "s3_bucket",
                                "resource_id": f"arn:aws:s3:::{bucket_name}",
                                "status": "NON_COMPLIANT",
                                "risk_level": "LOW",
                                "recommendation": "Enable S3 Intelligent Tiering configurations",
                                "details": {
                                    "bucket_name": bucket_name,
                                    "bucket_region": bucket_region,
                                    "violation": "Intelligent Tiering configurations exist but are not enabled",
                                    "intelligent_tiering_configs_count": len(intelligent_tiering_configs),
                                    "active_configs_count": 0
                                }
                            })
                
                except s3_client.exceptions.NoSuchConfiguration:
                    # No Intelligent Tiering configuration exists
                    findings.append({
                        "region": region_name,
                        "profile": profile_name or "default",
                        "resource_type": "s3_bucket",
                        "resource_id": f"arn:aws:s3:::{bucket_name}",
                        "status": "NON_COMPLIANT",
                        "risk_level": "LOW",
                        "recommendation": "Enable S3 Intelligent Tiering for cost optimization",
                        "details": {
                            "bucket_name": bucket_name,
                            "bucket_region": bucket_region,
                            "violation": "No Intelligent Tiering configuration found",
                            "intelligent_tiering_configs_count": 0
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
                    "risk_level": "LOW",
                    "recommendation": "Unable to check Intelligent Tiering configuration",
                    "details": {
                        "bucket_name": bucket_name,
                        "error": str(bucket_error)
                    }
                })
        
        logger.info(f"Completed checking s3_bucket_intelligent_tiering_enabled. Found {len(findings)} findings.")
        
    except Exception as e:
        logger.error(f"Failed to check s3_bucket_intelligent_tiering_enabled: {e}")
        findings.append({
            "region": region_name,
            "profile": profile_name or "default",
            "resource_type": "s3_bucket",
            "resource_id": "unknown",
            "status": "ERROR",
            "risk_level": "LOW",
            "recommendation": "Fix API access issues",
            "details": {
                "error": str(e)
            }
        })
    
    return findings

def s3_bucket_intelligent_tiering_enabled(region_name: str, profile_name: str = None) -> Dict[str, Any]:
    """
    Main function wrapper for s3_bucket_intelligent_tiering_enabled.
    
    Args:
        region_name (str): AWS region name
        profile_name (str): AWS profile name (optional)
        
    Returns:
        Dict: Results summary
    """
    COMPLIANCE_DATA = load_rule_metadata("s3_bucket_intelligent_tiering_enabled")
    
    # TODO: Implement SecurityEngine integration when available
    # from data_security_engine import SecurityEngine
    # engine = SecurityEngine(COMPLIANCE_DATA)
    # return engine.run_check(region_name, profile_name, s3_bucket_intelligent_tiering_enabled_check)
    
    # Current implementation
    findings = s3_bucket_intelligent_tiering_enabled_check(region_name, profile_name)
    
    # Calculate compliance statistics
    total_findings = len(findings)
    compliant_findings = len([f for f in findings if f['status'] == 'COMPLIANT'])
    non_compliant_findings = len([f for f in findings if f['status'] == 'NON_COMPLIANT'])
    error_findings = len([f for f in findings if f['status'] == 'ERROR'])
    
    return {
        "function_name": "s3_bucket_intelligent_tiering_enabled",
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
    """CLI entry point for s3_bucket_intelligent_tiering_enabled."""
    # TODO: Implement setup_command_line_interface() when data_security_engine is available
    # from data_security_engine import setup_command_line_interface, save_results, exit_with_status
    # args = setup_command_line_interface()
    # results = s3_bucket_intelligent_tiering_enabled(args.region, args.profile)
    # save_results(results, args.output_file)
    # exit_with_status(results)
    
    # Current CLI implementation
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Configure S3 Intelligent Tiering to automatically optimize storage costs while maintaining data accessibility and compliance."
    )
    parser.add_argument("--region", default="us-east-1", help="AWS region")
    parser.add_argument("--profile", help="AWS profile name")
    parser.add_argument("--output", help="Output file for results (JSON format)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        results = s3_bucket_intelligent_tiering_enabled(args.region, args.profile)
        
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

#!/usr/bin/env python3
"""
data_security_aws - glue_crawler_iam_least_privilege

Ensure Glue crawlers use IAM roles with least privilege to minimize unauthorized access to data sources.
"""

# Rule Metadata from YAML:
# Function Name: glue_crawler_iam_least_privilege
# Capability: ACCESS_GOVERNANCE
# Service: GLUE
# Subservice: IAM
# Description: Ensure Glue crawlers use IAM roles with least privilege to minimize unauthorized access to data sources.
# Risk Level: MEDIUM
# Recommendation: Enforce least privilege for Glue crawler IAM roles
# API Function: client = boto3.client('glue')
# User Function: glue_crawler_iam_least_privilege()

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
        "function_name": "glue_crawler_iam_least_privilege",
        "title": "Enforce least privilege for Glue crawler IAM roles",
        "description": "Ensure Glue crawlers use IAM roles with least privilege to minimize unauthorized access to data sources.",
        "capability": "access_governance",
        "service": "glue",
        "subservice": "iam",
        "risk": "MEDIUM",
        "existing": False
    }

def glue_crawler_iam_least_privilege_check(region_name: str, profile_name: str = None) -> List[Dict[str, Any]]:
    """
    Check glue resources for access_governance compliance.
    
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
        glue_client = session.client('glue', region_name=region_name)
        
        logger.info(f"Checking {service} resources for access_governance compliance in region {region_name}")
        
        # TODO: Implement specific logic for glue_crawler_iam_least_privilege
        # Example structure:
        # paginator = glue_client.get_paginator('list_resources')  # Replace with actual API call
        # for page in paginator.paginate():
        #     for resource in page['Resources']:
        #         resource_id = resource.get('ResourceId')
        #         resource_arn = resource.get('ResourceArn')
        #         
        #         if not_compliant_condition:
        #             findings.append({
        #                 "region": region_name,
        #                 "profile": profile_name or "default",
        #                 "resource_type": "glue_iam",
        #                 "resource_id": resource_arn,
        #                 "status": "NON_COMPLIANT",
        #                 "risk_level": "MEDIUM",
        #                 "recommendation": "Enforce least privilege for Glue crawler IAM roles",
        #                 "details": {
        #                     "glue_id": resource_arn,
        #                     "violation": "Specific violation details"
        #                 }
        #             })
        #         else:
        #             findings.append({
        #                 "region": region_name,
        #                 "profile": profile_name or "default",
        #                 "resource_type": "glue_iam",
        #                 "resource_id": resource_arn,
        #                 "status": "COMPLIANT",
        #                 "risk_level": "MEDIUM",
        #                 "recommendation": "Resource is compliant",
        #                 "details": {
        #                     "glue_id": resource_arn
        #                 }
        #             })
        
        logger.info(f"Completed checking glue_crawler_iam_least_privilege. Found {len(findings)} findings.")
        
    except Exception as e:
        logger.error(f"Failed to check glue_crawler_iam_least_privilege: {e}")
        findings.append({
            "region": region_name,
            "profile": profile_name or "default",
            "resource_type": "glue_iam",
            "resource_id": "unknown",
            "status": "ERROR",
            "risk_level": "MEDIUM",
            "recommendation": "Fix API access issues",
            "details": {
                "error": str(e)
            }
        })
    
    return findings

def glue_crawler_iam_least_privilege(region_name: str, profile_name: str = None) -> Dict[str, Any]:
    """
    Main function wrapper for glue_crawler_iam_least_privilege.
    
    Args:
        region_name (str): AWS region name
        profile_name (str): AWS profile name (optional)
        
    Returns:
        Dict: Results summary
    """
    COMPLIANCE_DATA = load_rule_metadata("glue_crawler_iam_least_privilege")
    
    # TODO: Implement SecurityEngine integration when available
    # from data_security_engine import SecurityEngine
    # engine = SecurityEngine(COMPLIANCE_DATA)
    # return engine.run_check(region_name, profile_name, glue_crawler_iam_least_privilege_check)
    
    # Current implementation
    findings = glue_crawler_iam_least_privilege_check(region_name, profile_name)
    
    # Calculate compliance statistics
    total_findings = len(findings)
    compliant_findings = len([f for f in findings if f['status'] == 'COMPLIANT'])
    non_compliant_findings = len([f for f in findings if f['status'] == 'NON_COMPLIANT'])
    error_findings = len([f for f in findings if f['status'] == 'ERROR'])
    
    return {
        "function_name": "glue_crawler_iam_least_privilege",
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
    """CLI entry point for glue_crawler_iam_least_privilege."""
    # TODO: Implement setup_command_line_interface() when data_security_engine is available
    # from data_security_engine import setup_command_line_interface, save_results, exit_with_status
    # args = setup_command_line_interface()
    # results = glue_crawler_iam_least_privilege(args.region, args.profile)
    # save_results(results, args.output_file)
    # exit_with_status(results)
    
    # Current CLI implementation
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Ensure Glue crawlers use IAM roles with least privilege to minimize unauthorized access to data sources."
    )
    parser.add_argument("--region", default="us-east-1", help="AWS region")
    parser.add_argument("--profile", help="AWS profile name")
    parser.add_argument("--output", help="Output file for results (JSON format)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        results = glue_crawler_iam_least_privilege(args.region, args.profile)
        
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

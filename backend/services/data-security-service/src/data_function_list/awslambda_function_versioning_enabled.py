#!/usr/bin/env python3
"""
data_security_aws - awslambda_function_versioning_enabled

Enable versioning for Lambda functions to maintain code integrity and support rollback capabilities.
"""

# Rule Metadata from YAML:
# Function Name: awslambda_function_versioning_enabled
# Capability: DATA_PROTECTION
# Service: LAMBDA
# Subservice: VERSIONING
# Description: Enable versioning for Lambda functions to maintain code integrity and support rollback capabilities.
# Risk Level: MEDIUM
# Recommendation: Enable versioning for Lambda functions
# API Function: client = boto3.client('lambda')
# User Function: awslambda_function_versioning_enabled()

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
        "function_name": "awslambda_function_versioning_enabled",
        "title": "Enable versioning for Lambda functions",
        "description": "Enable versioning for Lambda functions to maintain code integrity and support rollback capabilities.",
        "capability": "data_protection",
        "service": "lambda",
        "subservice": "versioning",
        "risk": "MEDIUM",
        "existing": False
    }

def awslambda_function_versioning_enabled_check(region_name: str, profile_name: str = None) -> List[Dict[str, Any]]:
    """
    Check lambda resources for data_protection compliance.
    
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
        lambda_client = session.client('lambda', region_name=region_name)
        
        logger.info(f"Checking lambda resources for data_protection compliance in region {region_name}")
        
        # Get all Lambda functions in the region
        paginator = lambda_client.get_paginator('list_functions')
        
        for page in paginator.paginate():
            for function in page['Functions']:
                function_name = function.get('FunctionName')
                function_arn = function.get('FunctionArn')
                
                try:
                    # Get function versions to check if versioning is enabled
                    versions_paginator = lambda_client.get_paginator('list_versions_by_function')
                    
                    # Get all versions for this function
                    versions = []
                    for version_page in versions_paginator.paginate(FunctionName=function_name):
                        versions.extend(version_page.get('Versions', []))
                    
                    # Filter out $LATEST version to get published versions
                    published_versions = [v for v in versions if v.get('Version') != '$LATEST']
                    
                    # Check if function has aliases (another indicator of versioning strategy)
                    try:
                        aliases_paginator = lambda_client.get_paginator('list_aliases')
                        aliases = []
                        for alias_page in aliases_paginator.paginate(FunctionName=function_name):
                            aliases.extend(alias_page.get('Aliases', []))
                    except Exception:
                        aliases = []
                    
                    # Determine compliance based on versioning practices
                    if len(published_versions) == 0 and len(aliases) == 0:
                        # No published versions and no aliases - not using versioning
                        findings.append({
                            "region": region_name,
                            "profile": profile_name or "default",
                            "resource_type": "lambda_function",
                            "resource_id": function_arn,
                            "status": "NON_COMPLIANT",
                            "risk_level": "MEDIUM",
                            "recommendation": "Enable versioning for Lambda function by publishing versions or creating aliases",
                            "details": {
                                "function_name": function_name,
                                "function_arn": function_arn,
                                "violation": "Lambda function has no published versions or aliases",
                                "published_versions_count": len(published_versions),
                                "aliases_count": len(aliases),
                                "current_version": next((v.get('Version') for v in versions if v.get('Version') == '$LATEST'), None),
                                "runtime": function.get('Runtime'),
                                "last_modified": function.get('LastModified')
                            }
                        })
                    elif len(published_versions) == 1 and len(aliases) == 0:
                        # Only one published version and no aliases - minimal versioning
                        findings.append({
                            "region": region_name,
                            "profile": profile_name or "default",
                            "resource_type": "lambda_function",
                            "resource_id": function_arn,
                            "status": "NON_COMPLIANT",
                            "risk_level": "MEDIUM",
                            "recommendation": "Improve versioning strategy by publishing multiple versions or using aliases",
                            "details": {
                                "function_name": function_name,
                                "function_arn": function_arn,
                                "violation": "Lambda function has minimal versioning (only 1 published version, no aliases)",
                                "published_versions_count": len(published_versions),
                                "aliases_count": len(aliases),
                                "published_versions": [v.get('Version') for v in published_versions],
                                "runtime": function.get('Runtime'),
                                "last_modified": function.get('LastModified')
                            }
                        })
                    else:
                        # Good versioning practices - multiple versions or aliases
                        latest_version = max([int(v.get('Version')) for v in published_versions if v.get('Version').isdigit()], default=0)
                        
                        findings.append({
                            "region": region_name,
                            "profile": profile_name or "default",
                            "resource_type": "lambda_function",
                            "resource_id": function_arn,
                            "status": "COMPLIANT",
                            "risk_level": "MEDIUM",
                            "recommendation": "Lambda function has proper versioning enabled",
                            "details": {
                                "function_name": function_name,
                                "function_arn": function_arn,
                                "published_versions_count": len(published_versions),
                                "aliases_count": len(aliases),
                                "latest_published_version": str(latest_version),
                                "aliases": [{"name": a.get('Name'), "version": a.get('FunctionVersion')} for a in aliases],
                                "runtime": function.get('Runtime'),
                                "last_modified": function.get('LastModified')
                            }
                        })
                        
                except Exception as func_error:
                    logger.warning(f"Failed to check versioning for function {function_name}: {func_error}")
                    findings.append({
                        "region": region_name,
                        "profile": profile_name or "default",
                        "resource_type": "lambda_function",
                        "resource_id": function_arn,
                        "status": "ERROR",
                        "risk_level": "MEDIUM",
                        "recommendation": "Unable to check Lambda function versioning",
                        "details": {
                            "function_name": function_name,
                            "function_arn": function_arn,
                            "error": str(func_error)
                        }
                    })
        
        logger.info(f"Completed checking awslambda_function_versioning_enabled. Found {len(findings)} findings.")
        
    except Exception as e:
        logger.error(f"Failed to check awslambda_function_versioning_enabled: {e}")
        findings.append({
            "region": region_name,
            "profile": profile_name or "default",
            "resource_type": "lambda_function",
            "resource_id": "unknown",
            "status": "ERROR",
            "risk_level": "MEDIUM",
            "recommendation": "Fix API access issues",
            "details": {
                "error": str(e)
            }
        })
    
    return findings

def awslambda_function_versioning_enabled(region_name: str, profile_name: str = None) -> Dict[str, Any]:
    """
    Main function wrapper for awslambda_function_versioning_enabled.
    
    Args:
        region_name (str): AWS region name
        profile_name (str): AWS profile name (optional)
        
    Returns:
        Dict: Results summary
    """
    COMPLIANCE_DATA = load_rule_metadata("awslambda_function_versioning_enabled")
    
    # TODO: Implement SecurityEngine integration when available
    # from data_security_engine import SecurityEngine
    # engine = SecurityEngine(COMPLIANCE_DATA)
    # return engine.run_check(region_name, profile_name, awslambda_function_versioning_enabled_check)
    
    # Current implementation
    findings = awslambda_function_versioning_enabled_check(region_name, profile_name)
    
    # Calculate compliance statistics
    total_findings = len(findings)
    compliant_findings = len([f for f in findings if f['status'] == 'COMPLIANT'])
    non_compliant_findings = len([f for f in findings if f['status'] == 'NON_COMPLIANT'])
    error_findings = len([f for f in findings if f['status'] == 'ERROR'])
    
    return {
        "function_name": "awslambda_function_versioning_enabled",
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
    """CLI entry point for awslambda_function_versioning_enabled."""
    # TODO: Implement setup_command_line_interface() when data_security_engine is available
    # from data_security_engine import setup_command_line_interface, save_results, exit_with_status
    # args = setup_command_line_interface()
    # results = awslambda_function_versioning_enabled(args.region, args.profile)
    # save_results(results, args.output_file)
    # exit_with_status(results)
    
    # Current CLI implementation
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Enable versioning for Lambda functions to maintain code integrity and support rollback capabilities."
    )
    parser.add_argument("--region", default="us-east-1", help="AWS region")
    parser.add_argument("--profile", help="AWS profile name")
    parser.add_argument("--output", help="Output file for results (JSON format)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        results = awslambda_function_versioning_enabled(args.region, args.profile)
        
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

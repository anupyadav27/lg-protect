#!/usr/bin/env python3
"""
data_security_aws - awslambda_function_code_signing_enabled

Enable code signing for Lambda functions to ensure code integrity and prevent unauthorized modifications.
"""

# Rule Metadata from YAML:
# Function Name: awslambda_function_code_signing_enabled
# Capability: DATA_PROTECTION
# Service: LAMBDA
# Subservice: SIGNING
# Description: Enable code signing for Lambda functions to ensure code integrity and prevent unauthorized modifications.
# Risk Level: MEDIUM
# Recommendation: Enable code signing for Lambda functions
# API Function: client = boto3.client('lambda')
# User Function: awslambda_function_code_signing_enabled()

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
        "function_name": "awslambda_function_code_signing_enabled",
        "title": "Enable code signing for Lambda functions",
        "description": "Enable code signing for Lambda functions to ensure code integrity and prevent unauthorized modifications.",
        "capability": "data_protection",
        "service": "lambda",
        "subservice": "signing",
        "risk": "MEDIUM",
        "existing": False
    }

def awslambda_function_code_signing_enabled_check(region_name: str, profile_name: str = None) -> List[Dict[str, Any]]:
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
                    # Get function configuration to check for code signing
                    function_config = lambda_client.get_function(FunctionName=function_name)
                    
                    # Check if code signing is enabled
                    code_signing_config_arn = function_config.get('Configuration', {}).get('CodeSigningConfigArn')
                    
                    if not code_signing_config_arn:
                        # Function does not have code signing enabled
                        findings.append({
                            "region": region_name,
                            "profile": profile_name or "default",
                            "resource_type": "lambda_function",
                            "resource_id": function_arn,
                            "status": "NON_COMPLIANT",
                            "risk_level": "MEDIUM",
                            "recommendation": "Enable code signing for Lambda function to ensure code integrity",
                            "details": {
                                "function_name": function_name,
                                "function_arn": function_arn,
                                "violation": "Code signing is not enabled for this Lambda function",
                                "runtime": function.get('Runtime'),
                                "last_modified": function.get('LastModified')
                            }
                        })
                    else:
                        # Verify the code signing configuration exists and is valid
                        try:
                            code_signing_response = lambda_client.get_code_signing_config(
                                CodeSigningConfigArn=code_signing_config_arn
                            )
                            
                            allowed_publishers = code_signing_response.get('CodeSigningConfig', {}).get('AllowedPublishers', {})
                            signing_profile_version_arns = allowed_publishers.get('SigningProfileVersionArns', [])
                            
                            if signing_profile_version_arns:
                                findings.append({
                                    "region": region_name,
                                    "profile": profile_name or "default",
                                    "resource_type": "lambda_function",
                                    "resource_id": function_arn,
                                    "status": "COMPLIANT",
                                    "risk_level": "MEDIUM",
                                    "recommendation": "Lambda function has code signing properly configured",
                                    "details": {
                                        "function_name": function_name,
                                        "function_arn": function_arn,
                                        "code_signing_config_arn": code_signing_config_arn,
                                        "signing_profiles_count": len(signing_profile_version_arns),
                                        "runtime": function.get('Runtime'),
                                        "last_modified": function.get('LastModified')
                                    }
                                })
                            else:
                                findings.append({
                                    "region": region_name,
                                    "profile": profile_name or "default",
                                    "resource_type": "lambda_function",
                                    "resource_id": function_arn,
                                    "status": "NON_COMPLIANT",
                                    "risk_level": "MEDIUM",
                                    "recommendation": "Code signing configuration exists but has no valid signing profiles",
                                    "details": {
                                        "function_name": function_name,
                                        "function_arn": function_arn,
                                        "code_signing_config_arn": code_signing_config_arn,
                                        "violation": "Code signing configuration has no allowed publishers/signing profiles",
                                        "runtime": function.get('Runtime'),
                                        "last_modified": function.get('LastModified')
                                    }
                                })
                                
                        except lambda_client.exceptions.ResourceNotFoundException:
                            findings.append({
                                "region": region_name,
                                "profile": profile_name or "default",
                                "resource_type": "lambda_function",
                                "resource_id": function_arn,
                                "status": "NON_COMPLIANT",
                                "risk_level": "MEDIUM",
                                "recommendation": "Code signing configuration ARN is invalid or does not exist",
                                "details": {
                                    "function_name": function_name,
                                    "function_arn": function_arn,
                                    "code_signing_config_arn": code_signing_config_arn,
                                    "violation": "Referenced code signing configuration does not exist",
                                    "runtime": function.get('Runtime'),
                                    "last_modified": function.get('LastModified')
                                }
                            })
                            
                except Exception as func_error:
                    logger.warning(f"Failed to check function {function_name}: {func_error}")
                    findings.append({
                        "region": region_name,
                        "profile": profile_name or "default",
                        "resource_type": "lambda_function",
                        "resource_id": function_arn,
                        "status": "ERROR",
                        "risk_level": "MEDIUM",
                        "recommendation": "Unable to check code signing configuration",
                        "details": {
                            "function_name": function_name,
                            "function_arn": function_arn,
                            "error": str(func_error)
                        }
                    })
        
        logger.info(f"Completed checking awslambda_function_code_signing_enabled. Found {len(findings)} findings.")
        
    except Exception as e:
        logger.error(f"Failed to check awslambda_function_code_signing_enabled: {e}")
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

def awslambda_function_code_signing_enabled(region_name: str, profile_name: str = None) -> Dict[str, Any]:
    """
    Main function wrapper for awslambda_function_code_signing_enabled.
    
    Args:
        region_name (str): AWS region name
        profile_name (str): AWS profile name (optional)
        
    Returns:
        Dict: Results summary
    """
    COMPLIANCE_DATA = load_rule_metadata("awslambda_function_code_signing_enabled")
    
    # TODO: Implement SecurityEngine integration when available
    # from data_security_engine import SecurityEngine
    # engine = SecurityEngine(COMPLIANCE_DATA)
    # return engine.run_check(region_name, profile_name, awslambda_function_code_signing_enabled_check)
    
    # Current implementation
    findings = awslambda_function_code_signing_enabled_check(region_name, profile_name)
    
    # Calculate compliance statistics
    total_findings = len(findings)
    compliant_findings = len([f for f in findings if f['status'] == 'COMPLIANT'])
    non_compliant_findings = len([f for f in findings if f['status'] == 'NON_COMPLIANT'])
    error_findings = len([f for f in findings if f['status'] == 'ERROR'])
    
    return {
        "function_name": "awslambda_function_code_signing_enabled",
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
    """CLI entry point for awslambda_function_code_signing_enabled."""
    # TODO: Implement setup_command_line_interface() when data_security_engine is available
    # from data_security_engine import setup_command_line_interface, save_results, exit_with_status
    # args = setup_command_line_interface()
    # results = awslambda_function_code_signing_enabled(args.region, args.profile)
    # save_results(results, args.output_file)
    # exit_with_status(results)
    
    # Current CLI implementation
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Enable code signing for Lambda functions to ensure code integrity and prevent unauthorized modifications."
    )
    parser.add_argument("--region", default="us-east-1", help="AWS region")
    parser.add_argument("--profile", help="AWS profile name")
    parser.add_argument("--output", help="Output file for results (JSON format)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        results = awslambda_function_code_signing_enabled(args.region, args.profile)
        
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

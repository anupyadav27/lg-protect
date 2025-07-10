#!/usr/bin/env python3
"""
data_security_aws - awslambda_function_environment_encryption_enabled

Ensure Lambda function environment variables are encrypted using KMS to protect sensitive configuration data.
"""

# Rule Metadata from YAML:
# Function Name: awslambda_function_environment_encryption_enabled
# Capability: DATA_PROTECTION
# Service: LAMBDA
# Subservice: ENCRYPTION
# Description: Ensure Lambda function environment variables are encrypted using KMS to protect sensitive configuration data.
# Risk Level: HIGH
# Recommendation: Enable encryption for Lambda environment variables
# API Function: client = boto3.client('lambda')
# User Function: awslambda_function_environment_encryption_enabled()

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
        "function_name": "awslambda_function_environment_encryption_enabled",
        "title": "Enable encryption for Lambda environment variables",
        "description": "Ensure Lambda function environment variables are encrypted using KMS to protect sensitive configuration data.",
        "capability": "data_protection",
        "service": "lambda",
        "subservice": "encryption",
        "risk": "HIGH",
        "existing": False
    }

def awslambda_function_environment_encryption_enabled_check(region_name: str, profile_name: str = None) -> List[Dict[str, Any]]:
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
                    # Get function configuration to check environment variables and encryption
                    function_config = lambda_client.get_function(FunctionName=function_name)
                    config = function_config.get('Configuration', {})
                    
                    # Check if function has environment variables
                    environment = config.get('Environment')
                    
                    if not environment or not environment.get('Variables'):
                        # Function has no environment variables - compliant by default
                        findings.append({
                            "region": region_name,
                            "profile": profile_name or "default",
                            "resource_type": "lambda_function",
                            "resource_id": function_arn,
                            "status": "COMPLIANT",
                            "risk_level": "HIGH",
                            "recommendation": "Lambda function has no environment variables requiring encryption",
                            "details": {
                                "function_name": function_name,
                                "function_arn": function_arn,
                                "has_environment_variables": False,
                                "runtime": function.get('Runtime'),
                                "last_modified": function.get('LastModified')
                            }
                        })
                    else:
                        # Function has environment variables - check encryption
                        environment_variables = environment.get('Variables', {})
                        kms_key_arn = environment.get('KMSKeyArn')
                        
                        if not kms_key_arn:
                            # Environment variables exist but are not encrypted with KMS
                            findings.append({
                                "region": region_name,
                                "profile": profile_name or "default",
                                "resource_type": "lambda_function",
                                "resource_id": function_arn,
                                "status": "NON_COMPLIANT",
                                "risk_level": "HIGH",
                                "recommendation": "Enable KMS encryption for Lambda function environment variables",
                                "details": {
                                    "function_name": function_name,
                                    "function_arn": function_arn,
                                    "violation": "Environment variables are not encrypted with KMS",
                                    "has_environment_variables": True,
                                    "environment_variables_count": len(environment_variables),
                                    "environment_variable_names": list(environment_variables.keys()),
                                    "kms_key_arn": None,
                                    "runtime": function.get('Runtime'),
                                    "last_modified": function.get('LastModified')
                                }
                            })
                        else:
                            # Verify KMS key exists and is accessible
                            try:
                                kms_client = session.client('kms', region_name=region_name)
                                
                                # Extract key ID from ARN or use directly
                                key_id = kms_key_arn.split('/')[-1] if '/' in kms_key_arn else kms_key_arn
                                
                                # Check if key exists and get its details
                                key_info = kms_client.describe_key(KeyId=key_id)
                                key_metadata = key_info.get('KeyMetadata', {})
                                
                                # Verify key is enabled
                                if key_metadata.get('KeyState') != 'Enabled':
                                    findings.append({
                                        "region": region_name,
                                        "profile": profile_name or "default",
                                        "resource_type": "lambda_function",
                                        "resource_id": function_arn,
                                        "status": "NON_COMPLIANT",
                                        "risk_level": "HIGH",
                                        "recommendation": "KMS key for environment variable encryption is not enabled",
                                        "details": {
                                            "function_name": function_name,
                                            "function_arn": function_arn,
                                            "violation": f"KMS key is in state: {key_metadata.get('KeyState')}",
                                            "has_environment_variables": True,
                                            "environment_variables_count": len(environment_variables),
                                            "kms_key_arn": kms_key_arn,
                                            "kms_key_state": key_metadata.get('KeyState'),
                                            "runtime": function.get('Runtime'),
                                            "last_modified": function.get('LastModified')
                                        }
                                    })
                                else:
                                    # Environment variables are properly encrypted
                                    findings.append({
                                        "region": region_name,
                                        "profile": profile_name or "default",
                                        "resource_type": "lambda_function",
                                        "resource_id": function_arn,
                                        "status": "COMPLIANT",
                                        "risk_level": "HIGH",
                                        "recommendation": "Lambda function environment variables are properly encrypted with KMS",
                                        "details": {
                                            "function_name": function_name,
                                            "function_arn": function_arn,
                                            "has_environment_variables": True,
                                            "environment_variables_count": len(environment_variables),
                                            "kms_key_arn": kms_key_arn,
                                            "kms_key_id": key_metadata.get('KeyId'),
                                            "kms_key_state": key_metadata.get('KeyState'),
                                            "kms_key_usage": key_metadata.get('KeyUsage'),
                                            "runtime": function.get('Runtime'),
                                            "last_modified": function.get('LastModified')
                                        }
                                    })
                                    
                            except Exception as kms_error:
                                findings.append({
                                    "region": region_name,
                                    "profile": profile_name or "default",
                                    "resource_type": "lambda_function",
                                    "resource_id": function_arn,
                                    "status": "NON_COMPLIANT",
                                    "risk_level": "HIGH",
                                    "recommendation": "KMS key for environment variable encryption is inaccessible or invalid",
                                    "details": {
                                        "function_name": function_name,
                                        "function_arn": function_arn,
                                        "violation": f"Cannot access KMS key: {str(kms_error)}",
                                        "has_environment_variables": True,
                                        "environment_variables_count": len(environment_variables),
                                        "kms_key_arn": kms_key_arn,
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
                        "risk_level": "HIGH",
                        "recommendation": "Unable to check environment variable encryption",
                        "details": {
                            "function_name": function_name,
                            "function_arn": function_arn,
                            "error": str(func_error)
                        }
                    })
        
        logger.info(f"Completed checking awslambda_function_environment_encryption_enabled. Found {len(findings)} findings.")
        
    except Exception as e:
        logger.error(f"Failed to check awslambda_function_environment_encryption_enabled: {e}")
        findings.append({
            "region": region_name,
            "profile": profile_name or "default",
            "resource_type": "lambda_function",
            "resource_id": "unknown",
            "status": "ERROR",
            "risk_level": "HIGH",
            "recommendation": "Fix API access issues",
            "details": {
                "error": str(e)
            }
        })
    
    return findings

def awslambda_function_environment_encryption_enabled(region_name: str, profile_name: str = None) -> Dict[str, Any]:
    """
    Main function wrapper for awslambda_function_environment_encryption_enabled.
    
    Args:
        region_name (str): AWS region name
        profile_name (str): AWS profile name (optional)
        
    Returns:
        Dict: Results summary
    """
    COMPLIANCE_DATA = load_rule_metadata("awslambda_function_environment_encryption_enabled")
    
    # TODO: Implement SecurityEngine integration when available
    # from data_security_engine import SecurityEngine
    # engine = SecurityEngine(COMPLIANCE_DATA)
    # return engine.run_check(region_name, profile_name, awslambda_function_environment_encryption_enabled_check)
    
    # Current implementation
    findings = awslambda_function_environment_encryption_enabled_check(region_name, profile_name)
    
    # Calculate compliance statistics
    total_findings = len(findings)
    compliant_findings = len([f for f in findings if f['status'] == 'COMPLIANT'])
    non_compliant_findings = len([f for f in findings if f['status'] == 'NON_COMPLIANT'])
    error_findings = len([f for f in findings if f['status'] == 'ERROR'])
    
    return {
        "function_name": "awslambda_function_environment_encryption_enabled",
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
    """CLI entry point for awslambda_function_environment_encryption_enabled."""
    # TODO: Implement setup_command_line_interface() when data_security_engine is available
    # from data_security_engine import setup_command_line_interface, save_results, exit_with_status
    # args = setup_command_line_interface()
    # results = awslambda_function_environment_encryption_enabled(args.region, args.profile)
    # save_results(results, args.output_file)
    # exit_with_status(results)
    
    # Current CLI implementation
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Ensure Lambda function environment variables are encrypted using KMS to protect sensitive configuration data."
    )
    parser.add_argument("--region", default="us-east-1", help="AWS region")
    parser.add_argument("--profile", help="AWS profile name")
    parser.add_argument("--output", help="Output file for results (JSON format)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        results = awslambda_function_environment_encryption_enabled(args.region, args.profile)
        
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

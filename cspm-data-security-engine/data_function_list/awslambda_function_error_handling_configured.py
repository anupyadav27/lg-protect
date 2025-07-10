#!/usr/bin/env python3
"""
data_security_aws - awslambda_function_error_handling_configured

Implement proper error handling in Lambda functions to prevent sensitive data exposure in error messages.
"""

# Rule Metadata from YAML:
# Function Name: awslambda_function_error_handling_configured
# Capability: DATA_PROTECTION
# Service: LAMBDA
# Subservice: ERROR_HANDLING
# Description: Implement proper error handling in Lambda functions to prevent sensitive data exposure in error messages.
# Risk Level: MEDIUM
# Recommendation: Configure error handling for Lambda functions
# API Function: client = boto3.client('lambda')
# User Function: awslambda_function_error_handling_configured()

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
        "function_name": "awslambda_function_error_handling_configured",
        "title": "Configure error handling for Lambda functions",
        "description": "Implement proper error handling in Lambda functions to prevent sensitive data exposure in error messages.",
        "capability": "data_protection",
        "service": "lambda",
        "subservice": "error_handling",
        "risk": "MEDIUM",
        "existing": False
    }

def awslambda_function_error_handling_configured_check(region_name: str, profile_name: str = None) -> List[Dict[str, Any]]:
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
                    # Get function configuration
                    function_config = lambda_client.get_function(FunctionName=function_name)
                    config = function_config.get('Configuration', {})
                    
                    # Check for error handling mechanisms
                    error_handling_violations = []
                    error_handling_features = []
                    
                    # Check for Dead Letter Queue configuration
                    dead_letter_config = config.get('DeadLetterConfig')
                    if not dead_letter_config or not dead_letter_config.get('TargetArn'):
                        error_handling_violations.append("No dead letter queue configured")
                    else:
                        error_handling_features.append({
                            'feature': 'Dead Letter Queue',
                            'target_arn': dead_letter_config.get('TargetArn')
                        })
                    
                    # Check for reserved concurrency (helps with error isolation)
                    try:
                        concurrency_response = lambda_client.get_provisioned_concurrency_config(
                            FunctionName=function_name
                        )
                        if concurrency_response:
                            error_handling_features.append({
                                'feature': 'Provisioned Concurrency',
                                'allocated_concurrency': concurrency_response.get('AllocatedProvisionedConcurrencyExecutions')
                            })
                    except lambda_client.exceptions.ProvisionedConcurrencyConfigNotFoundException:
                        # Check for reserved concurrency instead
                        try:
                            reserved_concurrency = config.get('ReservedConcurrencyExecutions')
                            if reserved_concurrency is not None:
                                error_handling_features.append({
                                    'feature': 'Reserved Concurrency',
                                    'reserved_concurrency': reserved_concurrency
                                })
                            else:
                                error_handling_violations.append("No concurrency limits configured")
                        except Exception:
                            error_handling_violations.append("Unable to check concurrency configuration")
                    except Exception:
                        error_handling_violations.append("Unable to check concurrency configuration")
                    
                    # Check timeout configuration (prevents long-running errors)
                    timeout = config.get('Timeout', 3)  # Default is 3 seconds
                    if timeout > 900:  # 15 minutes is max, but very long timeouts can be risky
                        error_handling_violations.append(f"Timeout too high: {timeout} seconds")
                    else:
                        error_handling_features.append({
                            'feature': 'Timeout Configuration',
                            'timeout_seconds': timeout
                        })
                    
                    # Check for retry configuration via event source mappings
                    try:
                        event_mappings = lambda_client.list_event_source_mappings(FunctionName=function_name)
                        retry_configurations = []
                        
                        for mapping in event_mappings.get('EventSourceMappings', []):
                            retry_config = {}
                            if 'MaximumRetryAttempts' in mapping:
                                retry_config['max_retry_attempts'] = mapping['MaximumRetryAttempts']
                            if 'BisectBatchOnFunctionError' in mapping:
                                retry_config['bisect_batch_on_error'] = mapping['BisectBatchOnFunctionError']
                            if 'MaximumRecordAgeInSeconds' in mapping:
                                retry_config['max_record_age'] = mapping['MaximumRecordAgeInSeconds']
                            
                            if retry_config:
                                retry_configurations.append({
                                    'event_source_arn': mapping.get('EventSourceArn'),
                                    'retry_config': retry_config
                                })
                        
                        if retry_configurations:
                            error_handling_features.append({
                                'feature': 'Event Source Retry Configuration',
                                'configurations': retry_configurations
                            })
                        
                    except Exception as retry_error:
                        logger.warning(f"Failed to check retry configuration for {function_name}: {retry_error}")
                    
                    # Check for destination configuration (for async error handling)
                    destinations_config = config.get('DestinationConfig')
                    if destinations_config:
                        destination_features = []
                        
                        on_success = destinations_config.get('OnSuccess', {})
                        if on_success.get('Destination'):
                            destination_features.append({
                                'type': 'OnSuccess',
                                'destination': on_success.get('Destination')
                            })
                        
                        on_failure = destinations_config.get('OnFailure', {})
                        if on_failure.get('Destination'):
                            destination_features.append({
                                'type': 'OnFailure',
                                'destination': on_failure.get('Destination')
                            })
                        
                        if destination_features:
                            error_handling_features.append({
                                'feature': 'Destination Configuration',
                                'destinations': destination_features
                            })
                        else:
                            error_handling_violations.append("Destination configuration exists but no destinations defined")
                    
                    # Check environment variables for error handling configuration
                    environment = config.get('Environment', {})
                    env_vars = environment.get('Variables', {})
                    
                    error_handling_env_vars = []
                    for var_name in env_vars.keys():
                        if any(keyword in var_name.upper() for keyword in ['ERROR', 'RETRY', 'TIMEOUT', 'LOG_LEVEL']):
                            error_handling_env_vars.append(var_name)
                    
                    if error_handling_env_vars:
                        error_handling_features.append({
                            'feature': 'Error Handling Environment Variables',
                            'variables': error_handling_env_vars
                        })
                    
                    # Determine compliance status
                    if len(error_handling_violations) > len(error_handling_features):
                        findings.append({
                            "region": region_name,
                            "profile": profile_name or "default",
                            "resource_type": "lambda_function",
                            "resource_id": function_arn,
                            "status": "NON_COMPLIANT",
                            "risk_level": "MEDIUM",
                            "recommendation": "Configure proper error handling mechanisms for Lambda function",
                            "details": {
                                "function_name": function_name,
                                "function_arn": function_arn,
                                "violation": "; ".join(error_handling_violations),
                                "missing_error_handling": error_handling_violations,
                                "configured_error_handling": error_handling_features,
                                "error_handling_score": len(error_handling_features),
                                "runtime": function.get('Runtime'),
                                "timeout": timeout,
                                "last_modified": function.get('LastModified')
                            }
                        })
                    else:
                        findings.append({
                            "region": region_name,
                            "profile": profile_name or "default",
                            "resource_type": "lambda_function",
                            "resource_id": function_arn,
                            "status": "COMPLIANT",
                            "risk_level": "MEDIUM",
                            "recommendation": "Lambda function has adequate error handling configured",
                            "details": {
                                "function_name": function_name,
                                "function_arn": function_arn,
                                "configured_error_handling": error_handling_features,
                                "error_handling_score": len(error_handling_features),
                                "minor_issues": error_handling_violations if error_handling_violations else None,
                                "runtime": function.get('Runtime'),
                                "timeout": timeout,
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
                        "recommendation": "Unable to check error handling configuration",
                        "details": {
                            "function_name": function_name,
                            "function_arn": function_arn,
                            "error": str(func_error)
                        }
                    })
        
        logger.info(f"Completed checking awslambda_function_error_handling_configured. Found {len(findings)} findings.")
        
    except Exception as e:
        logger.error(f"Failed to check awslambda_function_error_handling_configured: {e}")
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

def awslambda_function_error_handling_configured(region_name: str, profile_name: str = None) -> Dict[str, Any]:
    """
    Main function wrapper for awslambda_function_error_handling_configured.
    
    Args:
        region_name (str): AWS region name
        profile_name (str): AWS profile name (optional)
        
    Returns:
        Dict: Results summary
    """
    COMPLIANCE_DATA = load_rule_metadata("awslambda_function_error_handling_configured")
    
    # TODO: Implement SecurityEngine integration when available
    # from data_security_engine import SecurityEngine
    # engine = SecurityEngine(COMPLIANCE_DATA)
    # return engine.run_check(region_name, profile_name, awslambda_function_error_handling_configured_check)
    
    # Current implementation
    findings = awslambda_function_error_handling_configured_check(region_name, profile_name)
    
    # Calculate compliance statistics
    total_findings = len(findings)
    compliant_findings = len([f for f in findings if f['status'] == 'COMPLIANT'])
    non_compliant_findings = len([f for f in findings if f['status'] == 'NON_COMPLIANT'])
    error_findings = len([f for f in findings if f['status'] == 'ERROR'])
    
    return {
        "function_name": "awslambda_function_error_handling_configured",
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
    """CLI entry point for awslambda_function_error_handling_configured."""
    # TODO: Implement setup_command_line_interface() when data_security_engine is available
    # from data_security_engine import setup_command_line_interface, save_results, exit_with_status
    # args = setup_command_line_interface()
    # results = awslambda_function_error_handling_configured(args.region, args.profile)
    # save_results(results, args.output_file)
    # exit_with_status(results)
    
    # Current CLI implementation
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Implement proper error handling in Lambda functions to prevent sensitive data exposure in error messages."
    )
    parser.add_argument("--region", default="us-east-1", help="AWS region")
    parser.add_argument("--profile", help="AWS profile name")
    parser.add_argument("--output", help="Output file for results (JSON format)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        results = awslambda_function_error_handling_configured(args.region, args.profile)
        
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

#!/usr/bin/env python3
"""
data_security_aws - awslambda_function_dead_letter_queue_configured

Configure dead letter queues for Lambda functions to capture and analyze failed invocations for data integrity.
"""

# Rule Metadata from YAML:
# Function Name: awslambda_function_dead_letter_queue_configured
# Capability: DATA_PROTECTION
# Service: LAMBDA
# Subservice: DLQ
# Description: Configure dead letter queues for Lambda functions to capture and analyze failed invocations for data integrity.
# Risk Level: LOW
# Recommendation: Configure dead letter queues for Lambda functions
# API Function: client = boto3.client('lambda')
# User Function: awslambda_function_dead_letter_queue_configured()

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
        "function_name": "awslambda_function_dead_letter_queue_configured",
        "title": "Configure dead letter queues for Lambda functions",
        "description": "Configure dead letter queues for Lambda functions to capture and analyze failed invocations for data integrity.",
        "capability": "data_protection",
        "service": "lambda",
        "subservice": "dlq",
        "risk": "LOW",
        "existing": False
    }

def awslambda_function_dead_letter_queue_configured_check(region_name: str, profile_name: str = None) -> List[Dict[str, Any]]:
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
                    # Get function configuration to check for dead letter queue
                    function_config = lambda_client.get_function(FunctionName=function_name)
                    
                    # Check if dead letter queue is configured
                    dead_letter_config = function_config.get('Configuration', {}).get('DeadLetterConfig')
                    
                    if not dead_letter_config or not dead_letter_config.get('TargetArn'):
                        # Function does not have dead letter queue configured
                        findings.append({
                            "region": region_name,
                            "profile": profile_name or "default",
                            "resource_type": "lambda_function",
                            "resource_id": function_arn,
                            "status": "NON_COMPLIANT",
                            "risk_level": "LOW",
                            "recommendation": "Configure dead letter queue for Lambda function to capture failed invocations",
                            "details": {
                                "function_name": function_name,
                                "function_arn": function_arn,
                                "violation": "Dead letter queue is not configured for this Lambda function",
                                "runtime": function.get('Runtime'),
                                "timeout": function_config.get('Configuration', {}).get('Timeout'),
                                "memory_size": function_config.get('Configuration', {}).get('MemorySize'),
                                "last_modified": function.get('LastModified')
                            }
                        })
                    else:
                        # Validate the dead letter queue target
                        target_arn = dead_letter_config.get('TargetArn')
                        
                        # Check if target is valid (SQS or SNS)
                        is_valid_target = False
                        target_type = None
                        
                        if 'sqs' in target_arn.lower():
                            target_type = 'SQS'
                            is_valid_target = True
                        elif 'sns' in target_arn.lower():
                            target_type = 'SNS'
                            is_valid_target = True
                        
                        if is_valid_target:
                            # Verify the target resource exists and is accessible
                            try:
                                if target_type == 'SQS':
                                    sqs_client = session.client('sqs', region_name=region_name)
                                    queue_url = target_arn.split(':')[-1]
                                    # Try to get queue attributes to verify it exists
                                    sqs_client.get_queue_attributes(QueueUrl=queue_url, AttributeNames=['All'])
                                elif target_type == 'SNS':
                                    sns_client = session.client('sns', region_name=region_name)
                                    # Try to get topic attributes to verify it exists
                                    sns_client.get_topic_attributes(TopicArn=target_arn)
                                
                                findings.append({
                                    "region": region_name,
                                    "profile": profile_name or "default",
                                    "resource_type": "lambda_function",
                                    "resource_id": function_arn,
                                    "status": "COMPLIANT",
                                    "risk_level": "LOW",
                                    "recommendation": "Lambda function has dead letter queue properly configured",
                                    "details": {
                                        "function_name": function_name,
                                        "function_arn": function_arn,
                                        "dead_letter_queue_arn": target_arn,
                                        "dead_letter_queue_type": target_type,
                                        "runtime": function.get('Runtime'),
                                        "timeout": function_config.get('Configuration', {}).get('Timeout'),
                                        "memory_size": function_config.get('Configuration', {}).get('MemorySize'),
                                        "last_modified": function.get('LastModified')
                                    }
                                })
                                
                            except Exception as target_error:
                                findings.append({
                                    "region": region_name,
                                    "profile": profile_name or "default",
                                    "resource_type": "lambda_function",
                                    "resource_id": function_arn,
                                    "status": "NON_COMPLIANT",
                                    "risk_level": "LOW",
                                    "recommendation": "Dead letter queue target is inaccessible or does not exist",
                                    "details": {
                                        "function_name": function_name,
                                        "function_arn": function_arn,
                                        "dead_letter_queue_arn": target_arn,
                                        "violation": f"Dead letter queue target is not accessible: {str(target_error)}",
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
                                "risk_level": "LOW",
                                "recommendation": "Configure valid SQS or SNS target for dead letter queue",
                                "details": {
                                    "function_name": function_name,
                                    "function_arn": function_arn,
                                    "dead_letter_queue_arn": target_arn,
                                    "violation": "Dead letter queue target is not a valid SQS queue or SNS topic",
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
                        "risk_level": "LOW",
                        "recommendation": "Unable to check dead letter queue configuration",
                        "details": {
                            "function_name": function_name,
                            "function_arn": function_arn,
                            "error": str(func_error)
                        }
                    })
        
        logger.info(f"Completed checking awslambda_function_dead_letter_queue_configured. Found {len(findings)} findings.")
        
    except Exception as e:
        logger.error(f"Failed to check awslambda_function_dead_letter_queue_configured: {e}")
        findings.append({
            "region": region_name,
            "profile": profile_name or "default",
            "resource_type": "lambda_function",
            "resource_id": "unknown",
            "status": "ERROR",
            "risk_level": "LOW",
            "recommendation": "Fix API access issues",
            "details": {
                "error": str(e)
            }
        })
    
    return findings

def awslambda_function_dead_letter_queue_configured(region_name: str, profile_name: str = None) -> Dict[str, Any]:
    """
    Main function wrapper for awslambda_function_dead_letter_queue_configured.
    
    Args:
        region_name (str): AWS region name
        profile_name (str): AWS profile name (optional)
        
    Returns:
        Dict: Results summary
    """
    COMPLIANCE_DATA = load_rule_metadata("awslambda_function_dead_letter_queue_configured")
    
    # TODO: Implement SecurityEngine integration when available
    # from data_security_engine import SecurityEngine
    # engine = SecurityEngine(COMPLIANCE_DATA)
    # return engine.run_check(region_name, profile_name, awslambda_function_dead_letter_queue_configured_check)
    
    # Current implementation
    findings = awslambda_function_dead_letter_queue_configured_check(region_name, profile_name)
    
    # Calculate compliance statistics
    total_findings = len(findings)
    compliant_findings = len([f for f in findings if f['status'] == 'COMPLIANT'])
    non_compliant_findings = len([f for f in findings if f['status'] == 'NON_COMPLIANT'])
    error_findings = len([f for f in findings if f['status'] == 'ERROR'])
    
    return {
        "function_name": "awslambda_function_dead_letter_queue_configured",
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
    """CLI entry point for awslambda_function_dead_letter_queue_configured."""
    # TODO: Implement setup_command_line_interface() when data_security_engine is available
    # from data_security_engine import setup_command_line_interface, save_results, exit_with_status
    # args = setup_command_line_interface()
    # results = awslambda_function_dead_letter_queue_configured(args.region, args.profile)
    # save_results(results, args.output_file)
    # exit_with_status(results)
    
    # Current CLI implementation
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Configure dead letter queues for Lambda functions to capture and analyze failed invocations for data integrity."
    )
    parser.add_argument("--region", default="us-east-1", help="AWS region")
    parser.add_argument("--profile", help="AWS profile name")
    parser.add_argument("--output", help="Output file for results (JSON format)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        results = awslambda_function_dead_letter_queue_configured(args.region, args.profile)
        
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

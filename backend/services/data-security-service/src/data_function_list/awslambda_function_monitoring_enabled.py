#!/usr/bin/env python3
"""
data_security_aws - awslambda_function_monitoring_enabled

Enable comprehensive monitoring for Lambda functions to detect anomalies and potential data access issues.
"""

# Rule Metadata from YAML:
# Function Name: awslambda_function_monitoring_enabled
# Capability: DATA_PROTECTION
# Service: LAMBDA
# Subservice: MONITORING
# Description: Enable comprehensive monitoring for Lambda functions to detect anomalies and potential data access issues.
# Risk Level: LOW
# Recommendation: Enable monitoring for Lambda functions
# API Function: client = boto3.client('lambda')
# User Function: awslambda_function_monitoring_enabled()

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
        "function_name": "awslambda_function_monitoring_enabled",
        "title": "Enable monitoring for Lambda functions",
        "description": "Enable comprehensive monitoring for Lambda functions to detect anomalies and potential data access issues.",
        "capability": "data_protection",
        "service": "lambda",
        "subservice": "monitoring",
        "risk": "LOW",
        "existing": False
    }

def awslambda_function_monitoring_enabled_check(region_name: str, profile_name: str = None) -> List[Dict[str, Any]]:
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
        # Initialize boto3 clients
        session = boto3.Session(profile_name=profile_name)
        lambda_client = session.client('lambda', region_name=region_name)
        cloudwatch_client = session.client('cloudwatch', region_name=region_name)
        logs_client = session.client('logs', region_name=region_name)
        
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
                    
                    # Check monitoring capabilities
                    monitoring_violations = []
                    monitoring_features = []
                    
                    # Check X-Ray tracing configuration
                    tracing_config = config.get('TracingConfig', {})
                    tracing_mode = tracing_config.get('Mode', 'PassThrough')
                    
                    if tracing_mode == 'PassThrough':
                        monitoring_violations.append("X-Ray tracing is not enabled (PassThrough mode)")
                    elif tracing_mode == 'Active':
                        monitoring_features.append({
                            'feature': 'X-Ray Tracing',
                            'status': 'Active'
                        })
                    
                    # Check CloudWatch Logs configuration
                    log_group_name = f"/aws/lambda/{function_name}"
                    try:
                        log_groups_response = logs_client.describe_log_groups(
                            logGroupNamePrefix=log_group_name
                        )
                        
                        log_group_exists = False
                        log_retention_days = None
                        
                        for log_group in log_groups_response.get('logGroups', []):
                            if log_group.get('logGroupName') == log_group_name:
                                log_group_exists = True
                                log_retention_days = log_group.get('retentionInDays')
                                break
                        
                        if log_group_exists:
                            monitoring_features.append({
                                'feature': 'CloudWatch Logs',
                                'log_group': log_group_name,
                                'retention_days': log_retention_days
                            })
                            
                            if not log_retention_days:
                                monitoring_violations.append("CloudWatch Logs retention is not configured")
                        else:
                            monitoring_violations.append("CloudWatch Logs group does not exist")
                            
                    except Exception as logs_error:
                        logger.warning(f"Failed to check CloudWatch Logs for {function_name}: {logs_error}")
                        monitoring_violations.append("Unable to verify CloudWatch Logs configuration")
                    
                    # Check CloudWatch Metrics and Alarms
                    try:
                        # Check for CloudWatch alarms related to this function
                        alarms_response = cloudwatch_client.describe_alarms(
                            ActionPrefix=function_arn
                        )
                        
                        function_alarms = []
                        for alarm in alarms_response.get('MetricAlarms', []):
                            alarm_name = alarm.get('AlarmName')
                            if function_name in alarm_name or function_arn in str(alarm.get('AlarmActions', [])):
                                function_alarms.append({
                                    'alarm_name': alarm_name,
                                    'state': alarm.get('StateValue'),
                                    'metric_name': alarm.get('MetricName')
                                })
                        
                        if function_alarms:
                            monitoring_features.append({
                                'feature': 'CloudWatch Alarms',
                                'alarms': function_alarms,
                                'alarms_count': len(function_alarms)
                            })
                        else:
                            monitoring_violations.append("No CloudWatch alarms configured for the function")
                            
                    except Exception as alarms_error:
                        logger.warning(f"Failed to check CloudWatch Alarms for {function_name}: {alarms_error}")
                        monitoring_violations.append("Unable to verify CloudWatch Alarms")
                    
                    # Check function insights and performance monitoring
                    insights_arn = config.get('KMSKeyArn')  # This is actually for environment encryption
                    
                    # Check environment variables for monitoring configuration
                    environment = config.get('Environment', {})
                    env_vars = environment.get('Variables', {})
                    
                    monitoring_env_vars = []
                    for var_name in env_vars.keys():
                        if any(keyword in var_name.upper() for keyword in 
                               ['LOG_LEVEL', 'DEBUG', 'MONITORING', 'METRICS', 'TRACE']):
                            monitoring_env_vars.append(var_name)
                    
                    if monitoring_env_vars:
                        monitoring_features.append({
                            'feature': 'Monitoring Environment Variables',
                            'variables': monitoring_env_vars
                        })
                    
                    # Check for Lambda Insights (Enhanced Monitoring)
                    layers = config.get('Layers', [])
                    has_insights_layer = False
                    
                    for layer in layers:
                        layer_arn = layer.get('Arn', '')
                        if 'LambdaInsightsExtension' in layer_arn:
                            has_insights_layer = True
                            monitoring_features.append({
                                'feature': 'Lambda Insights',
                                'layer_arn': layer_arn
                            })
                            break
                    
                    if not has_insights_layer:
                        monitoring_violations.append("Lambda Insights layer is not configured")
                    
                    # Check dead letter queue for error monitoring
                    dead_letter_config = config.get('DeadLetterConfig')
                    if dead_letter_config and dead_letter_config.get('TargetArn'):
                        monitoring_features.append({
                            'feature': 'Dead Letter Queue',
                            'target_arn': dead_letter_config.get('TargetArn')
                        })
                    else:
                        monitoring_violations.append("Dead letter queue not configured for error monitoring")
                    
                    # Check function timeout (affects monitoring effectiveness)
                    timeout = config.get('Timeout', 3)
                    if timeout > 900:  # 15 minutes
                        monitoring_violations.append(f"Function timeout too high for effective monitoring: {timeout}s")
                    
                    # Calculate monitoring score
                    monitoring_score = len(monitoring_features)
                    monitoring_issues = len(monitoring_violations)
                    
                    # Determine compliance status
                    if monitoring_issues > monitoring_score or monitoring_score < 3:
                        findings.append({
                            "region": region_name,
                            "profile": profile_name or "default",
                            "resource_type": "lambda_function",
                            "resource_id": function_arn,
                            "status": "NON_COMPLIANT",
                            "risk_level": "LOW",
                            "recommendation": "Enable comprehensive monitoring for Lambda function",
                            "details": {
                                "function_name": function_name,
                                "function_arn": function_arn,
                                "violation": "; ".join(monitoring_violations),
                                "monitoring_violations": monitoring_violations,
                                "configured_monitoring": monitoring_features,
                                "monitoring_score": monitoring_score,
                                "tracing_mode": tracing_mode,
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
                            "risk_level": "LOW",
                            "recommendation": "Lambda function has comprehensive monitoring enabled",
                            "details": {
                                "function_name": function_name,
                                "function_arn": function_arn,
                                "configured_monitoring": monitoring_features,
                                "monitoring_score": monitoring_score,
                                "tracing_mode": tracing_mode,
                                "minor_issues": monitoring_violations if monitoring_violations else None,
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
                        "risk_level": "LOW",
                        "recommendation": "Unable to check monitoring configuration",
                        "details": {
                            "function_name": function_name,
                            "function_arn": function_arn,
                            "error": str(func_error)
                        }
                    })
        
        logger.info(f"Completed checking awslambda_function_monitoring_enabled. Found {len(findings)} findings.")
        
    except Exception as e:
        logger.error(f"Failed to check awslambda_function_monitoring_enabled: {e}")
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

def awslambda_function_monitoring_enabled(region_name: str, profile_name: str = None) -> Dict[str, Any]:
    """
    Main function wrapper for awslambda_function_monitoring_enabled.
    
    Args:
        region_name (str): AWS region name
        profile_name (str): AWS profile name (optional)
        
    Returns:
        Dict: Results summary
    """
    COMPLIANCE_DATA = load_rule_metadata("awslambda_function_monitoring_enabled")
    
    # TODO: Implement SecurityEngine integration when available
    # from data_security_engine import SecurityEngine
    # engine = SecurityEngine(COMPLIANCE_DATA)
    # return engine.run_check(region_name, profile_name, awslambda_function_monitoring_enabled_check)
    
    # Current implementation
    findings = awslambda_function_monitoring_enabled_check(region_name, profile_name)
    
    # Calculate compliance statistics
    total_findings = len(findings)
    compliant_findings = len([f for f in findings if f['status'] == 'COMPLIANT'])
    non_compliant_findings = len([f for f in findings if f['status'] == 'NON_COMPLIANT'])
    error_findings = len([f for f in findings if f['status'] == 'ERROR'])
    
    return {
        "function_name": "awslambda_function_monitoring_enabled",
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
    """CLI entry point for awslambda_function_monitoring_enabled."""
    # TODO: Implement setup_command_line_interface() when data_security_engine is available
    # from data_security_engine import setup_command_line_interface, save_results, exit_with_status
    # args = setup_command_line_interface()
    # results = awslambda_function_monitoring_enabled(args.region, args.profile)
    # save_results(results, args.output_file)
    # exit_with_status(results)
    
    # Current CLI implementation
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Enable comprehensive monitoring for Lambda functions to detect anomalies and potential data access issues."
    )
    parser.add_argument("--region", default="us-east-1", help="AWS region")
    parser.add_argument("--profile", help="AWS profile name")
    parser.add_argument("--output", help="Output file for results (JSON format)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        results = awslambda_function_monitoring_enabled(args.region, args.profile)
        
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

#!/usr/bin/env python3
"""
data_security_aws - dynamodb_table_access_patterns_monitored

Implement monitoring for unusual DynamoDB access patterns to detect potential data breaches or unauthorized access.
"""

# Rule Metadata from YAML:
# Function Name: dynamodb_table_access_patterns_monitored
# Capability: ACCESS_GOVERNANCE
# Service: DYNAMODB
# Subservice: MONITORING
# Description: Implement monitoring for unusual DynamoDB access patterns to detect potential data breaches or unauthorized access.
# Risk Level: LOW
# Recommendation: Monitor DynamoDB access patterns
# API Function: client = boto3.client('dynamodb')
# User Function: dynamodb_table_access_patterns_monitored()

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
        "function_name": "dynamodb_table_access_patterns_monitored",
        "title": "Monitor DynamoDB access patterns",
        "description": "Implement monitoring for unusual DynamoDB access patterns to detect potential data breaches or unauthorized access.",
        "capability": "access_governance",
        "service": "dynamodb",
        "subservice": "monitoring",
        "risk": "LOW",
        "existing": False
    }

def dynamodb_table_access_patterns_monitored_check(region_name: str, profile_name: str = None) -> List[Dict[str, Any]]:
    """
    Check dynamodb resources for access_governance compliance.
    
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
        dynamodb_client = session.client('dynamodb', region_name=region_name)
        cloudwatch_client = session.client('cloudwatch', region_name=region_name)
        logs_client = session.client('logs', region_name=region_name)
        
        logger.info(f"Checking dynamodb resources for access_governance compliance in region {region_name}")
        
        # Get all DynamoDB tables in the region
        paginator = dynamodb_client.get_paginator('list_tables')
        
        for page in paginator.paginate():
            for table_name in page.get('TableNames', []):
                try:
                    # Get table details
                    table_response = dynamodb_client.describe_table(TableName=table_name)
                    table = table_response.get('Table', {})
                    table_arn = table.get('TableArn')
                    
                    monitoring_violations = []
                    monitoring_features = []
                    
                    # Check CloudWatch metrics configuration
                    try:
                        # Check for custom CloudWatch metrics
                        metrics_response = cloudwatch_client.list_metrics(
                            Namespace='AWS/DynamoDB',
                            Dimensions=[
                                {
                                    'Name': 'TableName',
                                    'Value': table_name
                                }
                            ]
                        )
                        
                        available_metrics = [metric.get('MetricName') for metric in metrics_response.get('Metrics', [])]
                        
                        # Important metrics for access pattern monitoring
                        important_metrics = [
                            'ConsumedReadCapacityUnits',
                            'ConsumedWriteCapacityUnits',
                            'ThrottledRequests',
                            'UserErrors',
                            'SystemErrors'
                        ]
                        
                        monitored_metrics = [metric for metric in important_metrics if metric in available_metrics]
                        
                        if monitored_metrics:
                            monitoring_features.append({
                                'feature': 'CloudWatch Metrics',
                                'available_metrics': len(available_metrics),
                                'monitored_metrics': monitored_metrics
                            })
                        else:
                            monitoring_violations.append("No DynamoDB CloudWatch metrics available")
                            
                    except Exception as metrics_error:
                        logger.warning(f"Failed to check CloudWatch metrics for table {table_name}: {metrics_error}")
                        monitoring_violations.append("Unable to verify CloudWatch metrics")
                    
                    # Check for CloudWatch alarms
                    try:
                        alarms_response = cloudwatch_client.describe_alarms()
                        table_alarms = []
                        
                        for alarm in alarms_response.get('MetricAlarms', []):
                            alarm_name = alarm.get('AlarmName', '')
                            dimensions = alarm.get('Dimensions', [])
                            
                            # Check if alarm is related to this table
                            for dimension in dimensions:
                                if (dimension.get('Name') == 'TableName' and 
                                    dimension.get('Value') == table_name):
                                    table_alarms.append({
                                        'alarm_name': alarm_name,
                                        'metric_name': alarm.get('MetricName'),
                                        'threshold': alarm.get('Threshold'),
                                        'comparison_operator': alarm.get('ComparisonOperator'),
                                        'state': alarm.get('StateValue')
                                    })
                                    break
                        
                        if table_alarms:
                            monitoring_features.append({
                                'feature': 'CloudWatch Alarms',
                                'alarms_count': len(table_alarms),
                                'alarms': table_alarms[:3]  # Show first 3
                            })
                        else:
                            monitoring_violations.append("No CloudWatch alarms configured for table")
                            
                    except Exception as alarms_error:
                        logger.warning(f"Failed to check CloudWatch alarms for table {table_name}: {alarms_error}")
                        monitoring_violations.append("Unable to verify CloudWatch alarms")
                    
                    # Check for DynamoDB Streams (for change tracking)
                    stream_spec = table.get('StreamSpecification', {})
                    stream_enabled = stream_spec.get('StreamEnabled', False)
                    
                    if stream_enabled:
                        monitoring_features.append({
                            'feature': 'DynamoDB Streams',
                            'stream_view_type': stream_spec.get('StreamViewType'),
                            'stream_arn': table.get('LatestStreamArn')
                        })
                    else:
                        monitoring_violations.append("DynamoDB Streams not enabled for change tracking")
                    
                    # Check for Point-in-Time Recovery (indicates data protection awareness)
                    try:
                        pitr_response = dynamodb_client.describe_continuous_backups(TableName=table_name)
                        pitr_status = pitr_response.get('ContinuousBackupsDescription', {})
                        pitr_enabled = pitr_status.get('PointInTimeRecoveryDescription', {}).get('PointInTimeRecoveryStatus') == 'ENABLED'
                        
                        if pitr_enabled:
                            monitoring_features.append({
                                'feature': 'Point-in-Time Recovery',
                                'enabled': True
                            })
                        else:
                            monitoring_violations.append("Point-in-Time Recovery not enabled")
                            
                    except Exception as pitr_error:
                        logger.warning(f"Failed to check PITR for table {table_name}: {pitr_error}")
                        monitoring_violations.append("Unable to verify Point-in-Time Recovery")
                    
                    # Check for table-level encryption (security monitoring)
                    sse_description = table.get('SSEDescription', {})
                    encryption_type = sse_description.get('SSEType')
                    
                    if encryption_type:
                        monitoring_features.append({
                            'feature': 'Server-Side Encryption',
                            'encryption_type': encryption_type,
                            'kms_key_id': sse_description.get('KMSMasterKeyArn')
                        })
                    else:
                        monitoring_violations.append("Server-side encryption not configured")
                    
                    # Check for Global Tables (cross-region access patterns)
                    global_table_version = table.get('GlobalTableVersion')
                    replicas = table.get('Replicas', [])
                    
                    if global_table_version or replicas:
                        monitoring_features.append({
                            'feature': 'Global Tables',
                            'version': global_table_version,
                            'replicas_count': len(replicas)
                        })
                        
                        # Global tables require more sophisticated monitoring
                        if len(replicas) > 0 and len(table_alarms) == 0:
                            monitoring_violations.append("Global table lacks cross-region monitoring alarms")
                    
                    # Check for contributor insights (access pattern analysis)
                    try:
                        insights_response = dynamodb_client.describe_contributor_insights(
                            TableName=table_name
                        )
                        insights_status = insights_response.get('ContributorInsightsStatus')
                        
                        if insights_status == 'ENABLED':
                            monitoring_features.append({
                                'feature': 'Contributor Insights',
                                'status': insights_status
                            })
                        else:
                            monitoring_violations.append("Contributor Insights not enabled for access pattern analysis")
                            
                    except dynamodb_client.exceptions.ResourceNotFoundException:
                        monitoring_violations.append("Contributor Insights not configured")
                    except Exception as insights_error:
                        logger.warning(f"Failed to check Contributor Insights for table {table_name}: {insights_error}")
                    
                    # Check table capacity mode and scaling (affects access pattern monitoring)
                    billing_mode = table.get('BillingModeSummary', {}).get('BillingMode', 'PROVISIONED')
                    
                    if billing_mode == 'PAY_PER_REQUEST':
                        monitoring_features.append({
                            'feature': 'On-Demand Billing',
                            'mode': billing_mode
                        })
                    else:
                        # Check for auto-scaling configuration
                        provisioned_throughput = table.get('ProvisionedThroughput', {})
                        monitoring_features.append({
                            'feature': 'Provisioned Throughput',
                            'read_capacity': provisioned_throughput.get('ReadCapacityUnits'),
                            'write_capacity': provisioned_throughput.get('WriteCapacityUnits')
                        })
                        
                        # Provisioned mode should have scaling alarms
                        if not table_alarms:
                            monitoring_violations.append("Provisioned table lacks capacity monitoring alarms")
                    
                    # Check for tags related to monitoring or data classification
                    try:
                        tags_response = dynamodb_client.list_tags_of_resource(ResourceArn=table_arn)
                        tags = tags_response.get('Tags', [])
                        
                        monitoring_tags = []
                        for tag in tags:
                            tag_key = tag.get('Key', '').upper()
                            if any(keyword in tag_key for keyword in 
                                   ['MONITOR', 'ALERT', 'CRITICAL', 'SENSITIVE', 'COMPLIANCE']):
                                monitoring_tags.append({
                                    'key': tag.get('Key'),
                                    'value': tag.get('Value')
                                })
                        
                        if monitoring_tags:
                            monitoring_features.append({
                                'feature': 'Monitoring Tags',
                                'tags': monitoring_tags
                            })
                        
                    except Exception as tags_error:
                        logger.warning(f"Failed to check tags for table {table_name}: {tags_error}")
                    
                    # Calculate monitoring score
                    monitoring_score = len(monitoring_features)
                    monitoring_issues = len(monitoring_violations)
                    
                    # Determine compliance status
                    if monitoring_issues > monitoring_score or monitoring_score < 3:
                        findings.append({
                            "region": region_name,
                            "profile": profile_name or "default",
                            "resource_type": "dynamodb_table",
                            "resource_id": table_arn,
                            "status": "NON_COMPLIANT",
                            "risk_level": "LOW",
                            "recommendation": "Implement comprehensive access pattern monitoring for DynamoDB table",
                            "details": {
                                "table_name": table_name,
                                "table_arn": table_arn,
                                "violation": "; ".join(monitoring_violations),
                                "monitoring_violations": monitoring_violations,
                                "configured_monitoring": monitoring_features,
                                "monitoring_score": monitoring_score,
                                "billing_mode": billing_mode,
                                "stream_enabled": stream_enabled,
                                "table_status": table.get('TableStatus'),
                                "creation_date": table.get('CreationDateTime').isoformat() if table.get('CreationDateTime') else None
                            }
                        })
                    else:
                        findings.append({
                            "region": region_name,
                            "profile": profile_name or "default",
                            "resource_type": "dynamodb_table",
                            "resource_id": table_arn,
                            "status": "COMPLIANT",
                            "risk_level": "LOW",
                            "recommendation": "DynamoDB table has adequate access pattern monitoring",
                            "details": {
                                "table_name": table_name,
                                "table_arn": table_arn,
                                "configured_monitoring": monitoring_features,
                                "monitoring_score": monitoring_score,
                                "minor_issues": monitoring_violations if monitoring_violations else None,
                                "billing_mode": billing_mode,
                                "stream_enabled": stream_enabled,
                                "table_status": table.get('TableStatus'),
                                "creation_date": table.get('CreationDateTime').isoformat() if table.get('CreationDateTime') else None
                            }
                        })
                        
                except Exception as table_error:
                    logger.warning(f"Failed to check table {table_name}: {table_error}")
                    findings.append({
                        "region": region_name,
                        "profile": profile_name or "default",
                        "resource_type": "dynamodb_table",
                        "resource_id": f"table:{table_name}",
                        "status": "ERROR",
                        "risk_level": "LOW",
                        "recommendation": "Unable to check access pattern monitoring",
                        "details": {
                            "table_name": table_name,
                            "error": str(table_error)
                        }
                    })
        
        logger.info(f"Completed checking dynamodb_table_access_patterns_monitored. Found {len(findings)} findings.")
        
    except Exception as e:
        logger.error(f"Failed to check dynamodb_table_access_patterns_monitored: {e}")
        findings.append({
            "region": region_name,
            "profile": profile_name or "default",
            "resource_type": "dynamodb_table",
            "resource_id": "unknown",
            "status": "ERROR",
            "risk_level": "LOW",
            "recommendation": "Fix API access issues",
            "details": {
                "error": str(e)
            }
        })
    
    return findings

def dynamodb_table_access_patterns_monitored(region_name: str, profile_name: str = None) -> Dict[str, Any]:
    """
    Main function wrapper for dynamodb_table_access_patterns_monitored.
    
    Args:
        region_name (str): AWS region name
        profile_name (str): AWS profile name (optional)
        
    Returns:
        Dict: Results summary
    """
    COMPLIANCE_DATA = load_rule_metadata("dynamodb_table_access_patterns_monitored")
    
    # TODO: Implement SecurityEngine integration when available
    # from data_security_engine import SecurityEngine
    # engine = SecurityEngine(COMPLIANCE_DATA)
    # return engine.run_check(region_name, profile_name, dynamodb_table_access_patterns_monitored_check)
    
    # Current implementation
    findings = dynamodb_table_access_patterns_monitored_check(region_name, profile_name)
    
    # Calculate compliance statistics
    total_findings = len(findings)
    compliant_findings = len([f for f in findings if f['status'] == 'COMPLIANT'])
    non_compliant_findings = len([f for f in findings if f['status'] == 'NON_COMPLIANT'])
    error_findings = len([f for f in findings if f['status'] == 'ERROR'])
    
    return {
        "function_name": "dynamodb_table_access_patterns_monitored",
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
    """CLI entry point for dynamodb_table_access_patterns_monitored."""
    # TODO: Implement setup_command_line_interface() when data_security_engine is available
    # from data_security_engine import setup_command_line_interface, save_results, exit_with_status
    # args = setup_command_line_interface()
    # results = dynamodb_table_access_patterns_monitored(args.region, args.profile)
    # save_results(results, args.output_file)
    # exit_with_status(results)
    
    # Current CLI implementation
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Implement monitoring for unusual DynamoDB access patterns to detect potential data breaches or unauthorized access."
    )
    parser.add_argument("--region", default="us-east-1", help="AWS region")
    parser.add_argument("--profile", help="AWS profile name")
    parser.add_argument("--output", help="Output file for results (JSON format)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        results = dynamodb_table_access_patterns_monitored(args.region, args.profile)
        
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

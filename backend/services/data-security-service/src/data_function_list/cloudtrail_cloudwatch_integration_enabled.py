#!/usr/bin/env python3
"""
data_security_aws - cloudtrail_cloudwatch_integration_enabled

Enable CloudWatch integration for CloudTrail to monitor and alert on suspicious data access patterns.
"""

# Rule Metadata from YAML:
# Function Name: cloudtrail_cloudwatch_integration_enabled
# Capability: ACCESS_GOVERNANCE
# Service: CLOUDTRAIL
# Subservice: MONITORING
# Description: Enable CloudWatch integration for CloudTrail to monitor and alert on suspicious data access patterns.
# Risk Level: MEDIUM
# Recommendation: Enable CloudWatch integration for CloudTrail
# API Function: client = boto3.client('cloudtrail')
# User Function: cloudtrail_cloudwatch_integration_enabled()

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
        "function_name": "cloudtrail_cloudwatch_integration_enabled",
        "title": "Enable CloudWatch integration for CloudTrail",
        "description": "Enable CloudWatch integration for CloudTrail to monitor and alert on suspicious data access patterns.",
        "capability": "access_governance",
        "service": "cloudtrail",
        "subservice": "monitoring",
        "risk": "MEDIUM",
        "existing": False
    }

def cloudtrail_cloudwatch_integration_enabled_check(region_name: str, profile_name: str = None) -> List[Dict[str, Any]]:
    """
    Check cloudtrail resources for access_governance compliance.
    
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
        cloudtrail_client = session.client('cloudtrail', region_name=region_name)
        cloudwatch_client = session.client('cloudwatch', region_name=region_name)
        logs_client = session.client('logs', region_name=region_name)
        
        logger.info(f"Checking cloudtrail resources for access_governance compliance in region {region_name}")
        
        # Get all CloudTrail trails
        trails_response = cloudtrail_client.describe_trails()
        trails = trails_response.get('trailList', [])
        
        if not trails:
            findings.append({
                "region": region_name,
                "profile": profile_name or "default",
                "resource_type": "cloudtrail_trail",
                "resource_id": f"region:{region_name}",
                "status": "NON_COMPLIANT",
                "risk_level": "MEDIUM",
                "recommendation": "Create CloudTrail trails with CloudWatch integration",
                "details": {
                    "violation": "No CloudTrail trails found in region",
                    "region": region_name
                }
            })
            return findings
        
        for trail in trails:
            trail_name = trail.get('Name')
            trail_arn = trail.get('TrailARN')
            
            try:
                # Get trail status to check if it's enabled
                trail_status = cloudtrail_client.get_trail_status(Name=trail_name)
                is_logging = trail_status.get('IsLogging', False)
                
                cloudwatch_violations = []
                cloudwatch_features = []
                
                # Check CloudWatch Logs integration
                cloudwatch_logs_log_group_arn = trail.get('CloudWatchLogsLogGroupArn')
                cloudwatch_logs_role_arn = trail.get('CloudWatchLogsRoleArn')
                
                if not cloudwatch_logs_log_group_arn:
                    cloudwatch_violations.append("CloudWatch Logs integration not configured")
                else:
                    cloudwatch_features.append({
                        'feature': 'CloudWatch Logs Integration',
                        'log_group_arn': cloudwatch_logs_log_group_arn,
                        'role_arn': cloudwatch_logs_role_arn
                    })
                    
                    # Verify log group exists and is accessible
                    try:
                        log_group_name = cloudwatch_logs_log_group_arn.split(':')[-1]
                        log_group_response = logs_client.describe_log_groups(
                            logGroupNamePrefix=log_group_name
                        )
                        
                        log_group_found = False
                        retention_days = None
                        
                        for log_group in log_group_response.get('logGroups', []):
                            if log_group.get('logGroupName') == log_group_name:
                                log_group_found = True
                                retention_days = log_group.get('retentionInDays')
                                break
                        
                        if not log_group_found:
                            cloudwatch_violations.append("Referenced CloudWatch Logs group does not exist")
                        else:
                            cloudwatch_features.append({
                                'feature': 'CloudWatch Logs Group',
                                'log_group_name': log_group_name,
                                'retention_days': retention_days
                            })
                            
                            if not retention_days:
                                cloudwatch_violations.append("CloudWatch Logs retention not configured")
                                
                    except Exception as log_error:
                        logger.warning(f"Failed to verify log group for trail {trail_name}: {log_error}")
                        cloudwatch_violations.append("Unable to verify CloudWatch Logs configuration")
                
                # Check for CloudWatch alarms related to this trail
                try:
                    alarms_response = cloudwatch_client.describe_alarms()
                    trail_related_alarms = []
                    
                    for alarm in alarms_response.get('MetricAlarms', []):
                        alarm_name = alarm.get('AlarmName', '')
                        metric_name = alarm.get('MetricName', '')
                        namespace = alarm.get('Namespace', '')
                        
                        # Check if alarm is related to CloudTrail
                        if ('CloudTrail' in namespace or 
                            'cloudtrail' in alarm_name.lower() or
                            trail_name.lower() in alarm_name.lower() or
                            any(keyword in metric_name.lower() for keyword in 
                                ['error', 'unauthorized', 'root', 'console', 'policy'])):
                            
                            trail_related_alarms.append({
                                'alarm_name': alarm_name,
                                'metric_name': metric_name,
                                'namespace': namespace,
                                'state': alarm.get('StateValue')
                            })
                    
                    if trail_related_alarms:
                        cloudwatch_features.append({
                            'feature': 'CloudWatch Alarms',
                            'alarms': trail_related_alarms,
                            'alarms_count': len(trail_related_alarms)
                        })
                    else:
                        cloudwatch_violations.append("No CloudWatch alarms configured for trail monitoring")
                        
                except Exception as alarms_error:
                    logger.warning(f"Failed to check CloudWatch alarms for trail {trail_name}: {alarms_error}")
                    cloudwatch_violations.append("Unable to verify CloudWatch alarms")
                
                # Check metric filters if CloudWatch Logs is configured
                if cloudwatch_logs_log_group_arn:
                    try:
                        log_group_name = cloudwatch_logs_log_group_arn.split(':')[-1]
                        metric_filters_response = logs_client.describe_metric_filters(
                            logGroupName=log_group_name
                        )
                        
                        metric_filters = metric_filters_response.get('metricFilters', [])
                        
                        if metric_filters:
                            cloudwatch_features.append({
                                'feature': 'CloudWatch Metric Filters',
                                'filters_count': len(metric_filters),
                                'filters': [{'name': f.get('filterName'), 'pattern': f.get('filterPattern')} 
                                          for f in metric_filters[:5]]  # Show first 5
                            })
                        else:
                            cloudwatch_violations.append("No metric filters configured for CloudWatch Logs")
                            
                    except Exception as filters_error:
                        logger.warning(f"Failed to check metric filters for trail {trail_name}: {filters_error}")
                        cloudwatch_violations.append("Unable to verify metric filters")
                
                # Check for insights queries or dashboard integration
                insights_integration = []
                
                # Check event selectors for data events (more comprehensive monitoring)
                try:
                    event_selectors_response = cloudtrail_client.get_event_selectors(TrailName=trail_name)
                    event_selectors = event_selectors_response.get('EventSelectors', [])
                    
                    has_data_events = False
                    for selector in event_selectors:
                        if selector.get('IncludeManagementEvents', True):
                            insights_integration.append('management_events')
                        
                        data_resources = selector.get('DataResources', [])
                        if data_resources:
                            has_data_events = True
                            insights_integration.append('data_events')
                    
                    if has_data_events:
                        cloudwatch_features.append({
                            'feature': 'Data Events Monitoring',
                            'data_events_enabled': True
                        })
                    
                except Exception as selectors_error:
                    logger.warning(f"Failed to check event selectors for trail {trail_name}: {selectors_error}")
                
                # Calculate integration score
                integration_score = len(cloudwatch_features)
                integration_issues = len(cloudwatch_violations)
                
                # Check if trail is logging
                if not is_logging:
                    cloudwatch_violations.append("CloudTrail logging is disabled")
                
                # Determine compliance status
                if not is_logging or integration_issues > integration_score or integration_score < 2:
                    findings.append({
                        "region": region_name,
                        "profile": profile_name or "default",
                        "resource_type": "cloudtrail_trail",
                        "resource_id": trail_arn,
                        "status": "NON_COMPLIANT",
                        "risk_level": "MEDIUM",
                        "recommendation": "Enable comprehensive CloudWatch integration for CloudTrail",
                        "details": {
                            "trail_name": trail_name,
                            "trail_arn": trail_arn,
                            "violation": "; ".join(cloudwatch_violations),
                            "is_logging": is_logging,
                            "cloudwatch_violations": cloudwatch_violations,
                            "configured_features": cloudwatch_features,
                            "integration_score": integration_score,
                            "is_multi_region": trail.get('IsMultiRegionTrail', False),
                            "s3_bucket": trail.get('S3BucketName'),
                            "home_region": trail.get('HomeRegion')
                        }
                    })
                else:
                    findings.append({
                        "region": region_name,
                        "profile": profile_name or "default",
                        "resource_type": "cloudtrail_trail",
                        "resource_id": trail_arn,
                        "status": "COMPLIANT",
                        "risk_level": "MEDIUM",
                        "recommendation": "CloudTrail has good CloudWatch integration",
                        "details": {
                            "trail_name": trail_name,
                            "trail_arn": trail_arn,
                            "is_logging": is_logging,
                            "configured_features": cloudwatch_features,
                            "integration_score": integration_score,
                            "minor_issues": cloudwatch_violations if cloudwatch_violations else None,
                            "is_multi_region": trail.get('IsMultiRegionTrail', False),
                            "s3_bucket": trail.get('S3BucketName'),
                            "home_region": trail.get('HomeRegion')
                        }
                    })
                    
            except Exception as trail_error:
                logger.warning(f"Failed to check trail {trail_name}: {trail_error}")
                findings.append({
                    "region": region_name,
                    "profile": profile_name or "default",
                    "resource_type": "cloudtrail_trail",
                    "resource_id": trail_arn,
                    "status": "ERROR",
                    "risk_level": "MEDIUM",
                    "recommendation": "Unable to check CloudWatch integration",
                    "details": {
                        "trail_name": trail_name,
                        "trail_arn": trail_arn,
                        "error": str(trail_error)
                    }
                })
        
        logger.info(f"Completed checking cloudtrail_cloudwatch_integration_enabled. Found {len(findings)} findings.")
        
    except Exception as e:
        logger.error(f"Failed to check cloudtrail_cloudwatch_integration_enabled: {e}")
        findings.append({
            "region": region_name,
            "profile": profile_name or "default",
            "resource_type": "cloudtrail_trail",
            "resource_id": "unknown",
            "status": "ERROR",
            "risk_level": "MEDIUM",
            "recommendation": "Fix API access issues",
            "details": {
                "error": str(e)
            }
        })
    
    return findings

def cloudtrail_cloudwatch_integration_enabled(region_name: str, profile_name: str = None) -> Dict[str, Any]:
    """
    Main function wrapper for cloudtrail_cloudwatch_integration_enabled.
    
    Args:
        region_name (str): AWS region name
        profile_name (str): AWS profile name (optional)
        
    Returns:
        Dict: Results summary
    """
    COMPLIANCE_DATA = load_rule_metadata("cloudtrail_cloudwatch_integration_enabled")
    
    # TODO: Implement SecurityEngine integration when available
    # from data_security_engine import SecurityEngine
    # engine = SecurityEngine(COMPLIANCE_DATA)
    # return engine.run_check(region_name, profile_name, cloudtrail_cloudwatch_integration_enabled_check)
    
    # Current implementation
    findings = cloudtrail_cloudwatch_integration_enabled_check(region_name, profile_name)
    
    # Calculate compliance statistics
    total_findings = len(findings)
    compliant_findings = len([f for f in findings if f['status'] == 'COMPLIANT'])
    non_compliant_findings = len([f for f in findings if f['status'] == 'NON_COMPLIANT'])
    error_findings = len([f for f in findings if f['status'] == 'ERROR'])
    
    return {
        "function_name": "cloudtrail_cloudwatch_integration_enabled",
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
    """CLI entry point for cloudtrail_cloudwatch_integration_enabled."""
    # TODO: Implement setup_command_line_interface() when data_security_engine is available
    # from data_security_engine import setup_command_line_interface, save_results, exit_with_status
    # args = setup_command_line_interface()
    # results = cloudtrail_cloudwatch_integration_enabled(args.region, args.profile)
    # save_results(results, args.output_file)
    # exit_with_status(results)
    
    # Current CLI implementation
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Enable CloudWatch integration for CloudTrail to monitor and alert on suspicious data access patterns."
    )
    parser.add_argument("--region", default="us-east-1", help="AWS region")
    parser.add_argument("--profile", help="AWS profile name")
    parser.add_argument("--output", help="Output file for results (JSON format)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        results = cloudtrail_cloudwatch_integration_enabled(args.region, args.profile)
        
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

#!/usr/bin/env python3
"""
kisa_isms_p_2023_aws - cloudtrail_cloudwatch_logging_enabled

Change Management
"""

import sys
import os
import json
from typing import Dict, List, Any

# Add the core-engine path to sys.path to import compliance_engine
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from compliance_engine import (
    ComplianceEngine,
    setup_command_line_interface,
    save_results,
    exit_with_status
)

def load_compliance_metadata(function_name: str) -> dict:
    """Load compliance metadata including risk level and recommendation from JSON."""
    try:
        # Path to compliance_checks.json relative to functions_list directory
        compliance_json_path = os.path.join(
            os.path.dirname(__file__), 
            '..', '..', 
            'compliance_checks.json'
        )
        
        with open(compliance_json_path, 'r') as f:
            compliance_data = json.load(f)
        
        # Find the specific compliance entry for this function
        for entry in compliance_data:
            if entry.get('Function Name') == function_name:
                return {
                    'compliance_name': entry.get('Compliance Name', ''),
                    'function_name': entry.get('Function Name', ''),
                    'id': entry.get('ID', ''),
                    'name': entry.get('Name', ''),
                    'description': entry.get('Description', ''),
                    'api_function': entry.get('API function', ''),
                    'user_function': entry.get('user function', ''),
                    'risk_level': entry.get('Risk Level', 'MEDIUM'),
                    'recommendation': entry.get('Recommendation', 'Review and remediate as needed')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'kisa_isms_p_2023_aws',
        'function_name': 'cloudtrail_cloudwatch_logging_enabled',
        'id': '2.9.1',
        'name': 'Change Management',
        'description': 'Procedures must be established and implemented to manage all changes to assets related to information systems, and the impact on system performance and security must be analyzed before changes are made.',
        'api_function': 'client = boto3.client(\'cloudtrail\')',
        'user_function': 'describe_trails()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Enable CloudWatch logging for CloudTrail trails to ensure proper change management monitoring'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('cloudtrail_cloudwatch_logging_enabled')

def cloudtrail_cloudwatch_logging_enabled_check(cloudtrail_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for cloudtrail_cloudwatch_logging_enabled.
    
    Args:
        cloudtrail_client: Boto3 CloudTrail client (auto-created by framework)
        region (str): AWS region (auto-managed by framework)
        profile (str): AWS profile name (auto-managed by framework)
        logger: Logger instance (auto-configured by framework)
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    try:
        # Get all CloudTrail trails
        response = cloudtrail_client.describe_trails()
        trails = response.get('trailList', [])
        
        if not trails:
            findings.append({
                'region': region,
                'profile': profile,
                'resource_type': 'CloudTrail',
                'resource_id': 'no-trails',
                'status': 'NON_COMPLIANT',
                'compliance_status': 'FAIL',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                'recommendation': COMPLIANCE_DATA.get('recommendation', 'Create CloudTrail trails with CloudWatch Logs integration'),
                'details': {
                    'issue': 'No CloudTrail trails found',
                    'trails_count': 0
                }
            })
            return findings
        
        compliant_trails = []
        non_compliant_trails = []
        
        for trail in trails:
            trail_name = trail.get('Name', 'unknown')
            trail_arn = trail.get('TrailARN', 'unknown')
            cloud_watch_logs_log_group_arn = trail.get('CloudWatchLogsLogGroupArn')
            cloud_watch_logs_role_arn = trail.get('CloudWatchLogsRoleArn')
            home_region = trail.get('HomeRegion', 'unknown')
            s3_bucket_name = trail.get('S3BucketName', 'unknown')
            
            # Get trail status for additional details
            try:
                status_response = cloudtrail_client.get_trail_status(Name=trail_name)
                is_logging = status_response.get('IsLogging', False)
                latest_cloud_watch_logs_delivery_time = status_response.get('LatestCloudWatchLogsDeliveryTime')
                latest_cloud_watch_logs_delivery_error = status_response.get('LatestCloudWatchLogsDeliveryError')
                
            except Exception as e:
                logger.warning(f"Could not get trail status for {trail_name}: {e}")
                is_logging = False
                latest_cloud_watch_logs_delivery_time = None
                latest_cloud_watch_logs_delivery_error = str(e)
            
            # Check if CloudWatch Logs integration is properly configured
            has_cloudwatch_logs = bool(cloud_watch_logs_log_group_arn and cloud_watch_logs_role_arn)
            
            trail_details = {
                'trail_name': trail_name,
                'trail_arn': trail_arn,
                'has_cloudwatch_logs': has_cloudwatch_logs,
                'cloud_watch_logs_log_group_arn': cloud_watch_logs_log_group_arn,
                'cloud_watch_logs_role_arn': cloud_watch_logs_role_arn,
                'is_logging': is_logging,
                'home_region': home_region,
                's3_bucket_name': s3_bucket_name,
                'latest_cloud_watch_logs_delivery_time': latest_cloud_watch_logs_delivery_time.isoformat() if latest_cloud_watch_logs_delivery_time else None,
                'latest_cloud_watch_logs_delivery_error': latest_cloud_watch_logs_delivery_error
            }
            
            if has_cloudwatch_logs and is_logging:
                compliant_trails.append(trail_details)
                
                findings.append({
                    'region': region,
                    'profile': profile,
                    'resource_type': 'CloudTrail',
                    'resource_id': trail_name,
                    'status': 'COMPLIANT',
                    'compliance_status': 'PASS',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                    'recommendation': 'CloudTrail CloudWatch Logs integration is properly configured',
                    'details': trail_details
                })
            else:
                non_compliant_trails.append(trail_details)
                
                # Determine specific issue
                if not has_cloudwatch_logs:
                    issue = 'CloudWatch Logs integration not configured'
                elif not is_logging:
                    issue = 'CloudTrail logging is disabled'
                else:
                    issue = 'Unknown CloudWatch Logs integration issue'
                
                trail_details['issue'] = issue
                
                findings.append({
                    'region': region,
                    'profile': profile,
                    'resource_type': 'CloudTrail',
                    'resource_id': trail_name,
                    'status': 'NON_COMPLIANT',
                    'compliance_status': 'FAIL',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', f'Configure CloudWatch Logs integration: {issue}'),
                    'details': trail_details
                })
        
        # Add summary finding
        if compliant_trails and not non_compliant_trails:
            summary_status = 'COMPLIANT'
            summary_compliance = 'PASS'
            summary_message = 'All CloudTrail trails have CloudWatch Logs integration enabled'
        elif non_compliant_trails and not compliant_trails:
            summary_status = 'NON_COMPLIANT'
            summary_compliance = 'FAIL'
            summary_message = 'No CloudTrail trails have CloudWatch Logs integration enabled'
        else:
            summary_status = 'NON_COMPLIANT'
            summary_compliance = 'FAIL'
            summary_message = f'{len(compliant_trails)} trails compliant, {len(non_compliant_trails)} trails non-compliant'
        
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'CloudTrail Summary',
            'resource_id': f'cloudwatch-logs-{region}',
            'status': summary_status,
            'compliance_status': summary_compliance,
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': summary_message,
            'details': {
                'total_trails': len(trails),
                'compliant_trails': len(compliant_trails),
                'non_compliant_trails': len(non_compliant_trails),
                'compliant_trail_names': [t['trail_name'] for t in compliant_trails],
                'non_compliant_trail_names': [t['trail_name'] for t in non_compliant_trails]
            }
        })
        
    except Exception as e:
        logger.error(f"Error in cloudtrail_cloudwatch_logging_enabled check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'CloudTrail',
            'resource_id': f'cloudwatch-logs-{region}',
            'status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Review and remediate as needed'),
            'error': str(e)
        })
        
    return findings

def cloudtrail_cloudwatch_logging_enabled(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=cloudtrail_cloudwatch_logging_enabled_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = cloudtrail_cloudwatch_logging_enabled(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

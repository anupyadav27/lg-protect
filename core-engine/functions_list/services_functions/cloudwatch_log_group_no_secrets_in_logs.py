#!/usr/bin/env python3
"""
iso27001_2022_aws - cloudwatch_log_group_no_secrets_in_logs

Networks, systems and applications should be monitored for anomalous behaviour and appropriate actions taken to evaluate potential information security incidents.
"""

import sys
import os
import json
import re
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
                    'risk_level': entry.get('Risk Level', 'HIGH'),
                    'recommendation': entry.get('Recommendation', 'Review and remediate as needed')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'iso27001_2022_aws',
        'function_name': 'cloudwatch_log_group_no_secrets_in_logs',
        'id': 'A.12.4.1',
        'name': 'Event logging',
        'description': 'Networks, systems and applications should be monitored for anomalous behaviour and appropriate actions taken to evaluate potential information security incidents.',
        'api_function': 'client = boto3.client(\'logs\')',
        'user_function': 'filter_log_events()',
        'risk_level': 'HIGH',
        'recommendation': 'Ensure no secrets are logged in CloudWatch log groups'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('cloudwatch_log_group_no_secrets_in_logs')

def cloudwatch_log_group_no_secrets_in_logs_check(logs_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for cloudwatch_log_group_no_secrets_in_logs.
    
    Args:
        logs_client: Boto3 CloudWatch Logs client (auto-created by framework)
        region (str): AWS region (auto-managed by framework)
        profile (str): AWS profile name (auto-managed by framework)
        logger: Logger instance (auto-configured by framework)
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    try:
        # Get all log groups
        log_groups = []
        paginator = logs_client.get_paginator('describe_log_groups')
        
        for page in paginator.paginate():
            log_groups.extend(page.get('logGroups', []))
        
        if not log_groups:
            # No log groups found - compliant by default
            findings.append({
                'region': region,
                'profile': profile,
                'resource_type': 'CloudWatch Logs',
                'resource_id': f'no-log-groups-{region}',
                'status': 'COMPLIANT',
                'compliance_status': 'PASS',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                'recommendation': 'No CloudWatch log groups found',
                'details': {
                    'log_group_count': 0,
                    'message': 'No CloudWatch log groups exist in this region'
                }
            })
            return findings
        
        # Secret patterns to look for in logs
        secret_patterns = [
            r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']?([^\s"\']{8,})',
            r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\']?([^\s"\']{20,})',
            r'(?i)(secret[_-]?key|secretkey)\s*[=:]\s*["\']?([^\s"\']{20,})',
            r'(?i)(access[_-]?key|accesskey)\s*[=:]\s*["\']?([A-Z0-9]{20})',
            r'(?i)(private[_-]?key|privatekey)',
            r'(?i)-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----',
            r'(?i)(token)\s*[=:]\s*["\']?([^\s"\']{30,})',
            r'(?i)(client[_-]?secret|clientsecret)\s*[=:]\s*["\']?([^\s"\']{20,})',
            r'(?i)(database[_-]?password|db[_-]?password)',
            r'(?i)(aws[_-]?secret[_-]?access[_-]?key)',
        ]
        
        compiled_patterns = [re.compile(pattern) for pattern in secret_patterns]
        
        for log_group in log_groups:
            log_group_name = log_group.get('logGroupName', '')
            
            # Sample recent log events to check for secrets
            secrets_found = []
            
            try:
                # Get log streams for this log group
                streams_response = logs_client.describe_log_streams(
                    logGroupName=log_group_name,
                    orderBy='LastEventTime',
                    descending=True,
                    limit=5  # Check only recent streams
                )
                
                log_streams = streams_response.get('logStreams', [])
                
                for stream in log_streams[:3]:  # Check max 3 recent streams
                    stream_name = stream.get('logStreamName', '')
                    
                    try:
                        # Get recent log events from this stream
                        events_response = logs_client.filter_log_events(
                            logGroupName=log_group_name,
                            logStreamNames=[stream_name],
                            limit=50  # Check recent 50 events
                        )
                        
                        events = events_response.get('events', [])
                        
                        for event in events:
                            message = event.get('message', '')
                            timestamp = event.get('timestamp', 0)
                            
                            # Check message against secret patterns
                            for i, pattern in enumerate(compiled_patterns):
                                matches = pattern.findall(message)
                                if matches:
                                    secrets_found.append({
                                        'stream_name': stream_name,
                                        'timestamp': timestamp,
                                        'pattern_type': secret_patterns[i],
                                        'matches_count': len(matches),
                                        'message_snippet': message[:200] + '...' if len(message) > 200 else message
                                    })
                                    
                                    # Limit findings per log group to avoid overwhelming results
                                    if len(secrets_found) >= 5:
                                        break
                            
                            if len(secrets_found) >= 5:
                                break
                        
                        if len(secrets_found) >= 5:
                            break
                            
                    except Exception as event_error:
                        logger.warning(f"Error checking events in stream {stream_name}: {event_error}")
                        continue
                
            except Exception as stream_error:
                logger.warning(f"Error checking streams in log group {log_group_name}: {stream_error}")
                continue
            
            # Determine compliance status for this log group
            if secrets_found:
                status = 'NON_COMPLIANT'
                compliance_status = 'FAIL'
                recommendation = COMPLIANCE_DATA.get('recommendation', 'Ensure no secrets are logged in CloudWatch log groups')
            else:
                status = 'COMPLIANT'
                compliance_status = 'PASS'
                recommendation = 'No secrets detected in recent log events'
            
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'CloudWatch Log Group',
                'resource_id': log_group_name,
                'status': status,
                'compliance_status': compliance_status,
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                'recommendation': recommendation,
                'details': {
                    'log_group_name': log_group_name,
                    'creation_time': log_group.get('creationTime'),
                    'retention_in_days': log_group.get('retentionInDays'),
                    'stored_bytes': log_group.get('storedBytes', 0),
                    'secrets_found': secrets_found,
                    'secrets_count': len(secrets_found),
                    'checked_streams': len(log_streams[:3]),
                    'total_streams': len(log_streams)
                }
            }
            
            findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in cloudwatch_log_group_no_secrets_in_logs check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'CloudWatch Logs',
            'resource_id': f'check-error-{region}',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Review and remediate as needed'),
            'error': str(e)
        })
        
    return findings

def cloudwatch_log_group_no_secrets_in_logs(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=cloudwatch_log_group_no_secrets_in_logs_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = cloudwatch_log_group_no_secrets_in_logs(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

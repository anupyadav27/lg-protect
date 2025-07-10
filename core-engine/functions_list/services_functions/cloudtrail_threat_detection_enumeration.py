#!/usr/bin/env python3
"""
kisa_isms_p_2023_aws - cloudtrail_threat_detection_enumeration

To ensure normal use of the information system and prevent misuse (unauthorized access, excessive queries, etc.) by users, log review criteria for access and usage must be established and inspected periodically, and post-event actions must be taken promptly if issues arise.
"""

import sys
import os
import json
from typing import Dict, List, Any
from datetime import datetime, timedelta

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
                    'recommendation': entry.get('Recommendation', 'Review and remediate enumeration attempts immediately')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'kisa_isms_p_2023_aws',
        'function_name': 'cloudtrail_threat_detection_enumeration',
        'id': 'KISA-ISMS-P-2023-AWS-ENUM',
        'name': 'CloudTrail Enumeration Detection',
        'description': 'To ensure normal use of the information system and prevent misuse (unauthorized access, excessive queries, etc.) by users, log review criteria for access and usage must be established and inspected periodically, and post-event actions must be taken promptly if issues arise.',
        'api_function': 'client = boto3.client(\'cloudtrail\')',
        'user_function': 'lookup_events()',
        'risk_level': 'HIGH',
        'recommendation': 'Review and remediate enumeration attempts immediately'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('cloudtrail_threat_detection_enumeration')

def cloudtrail_threat_detection_enumeration_check(cloudtrail_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform CloudTrail enumeration detection check.
    
    Args:
        cloudtrail_client: Boto3 CloudTrail client
        region (str): AWS region
        profile (str): AWS profile name
        logger: Logger instance
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    # Enumeration events to monitor (reconnaissance activities)
    enumeration_events = [
        'List*',
        'Describe*',
        'Get*',
        'ListBuckets',
        'ListUsers',
        'ListRoles',
        'ListPolicies',
        'DescribeInstances',
        'DescribeSecurityGroups',
        'DescribeVpcs',
        'DescribeSubnets',
        'GetAccountSummary',
        'GetUser',
        'GetRole',
        'ListAttachedUserPolicies',
        'ListAttachedRolePolicies'
    ]
    
    try:
        # Look for enumeration patterns in the last 24 hours
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=24)
        
        suspicious_patterns = []
        user_event_counts = {}
        ip_event_counts = {}
        
        # Check for high volume enumeration from specific users or IPs
        for event_pattern in ['List', 'Describe', 'Get']:
            try:
                response = cloudtrail_client.lookup_events(
                    StartTime=start_time,
                    EndTime=end_time
                )
                
                for event in response.get('Events', []):
                    event_name = event.get('EventName', '')
                    
                    # Check if event matches enumeration patterns
                    if event_name.startswith(event_pattern):
                        username = event.get('Username', 'unknown')
                        source_ip = event.get('SourceIPAddress', 'unknown')
                        event_time = event.get('EventTime')
                        
                        # Count events by user
                        if username not in user_event_counts:
                            user_event_counts[username] = []
                        user_event_counts[username].append({
                            'event_name': event_name,
                            'event_time': event_time.isoformat() if event_time else 'unknown',
                            'source_ip': source_ip
                        })
                        
                        # Count events by IP
                        if source_ip not in ip_event_counts:
                            ip_event_counts[source_ip] = []
                        ip_event_counts[source_ip].append({
                            'event_name': event_name,
                            'event_time': event_time.isoformat() if event_time else 'unknown',
                            'username': username
                        })
                    
            except Exception as e:
                logger.warning(f"Error looking up {event_pattern} events: {e}")
                continue
        
        # Analyze patterns for suspicious activity
        # Flag users with more than 200 enumeration events in 24 hours
        for username, events in user_event_counts.items():
            if len(events) > 200:
                suspicious_patterns.append({
                    'type': 'High Volume User Enumeration',
                    'username': username,
                    'event_count': len(events),
                    'sample_events': events[:5],  # First 5 events as sample
                    'risk_reason': f'User {username} performed {len(events)} enumeration events in 24h',
                    'unique_ips': len(set(event['source_ip'] for event in events))
                })
        
        # Flag IPs with more than 300 enumeration events in 24 hours
        for source_ip, events in ip_event_counts.items():
            if len(events) > 300:
                suspicious_patterns.append({
                    'type': 'High Volume IP Enumeration',
                    'source_ip': source_ip,
                    'event_count': len(events),
                    'sample_events': events[:5],  # First 5 events as sample
                    'risk_reason': f'IP {source_ip} performed {len(events)} enumeration events in 24h',
                    'unique_users': len(set(event['username'] for event in events))
                })
        
        # Check for rapid enumeration (many events in short time)
        for username, events in user_event_counts.items():
            if len(events) > 50:  # Only check users with significant activity
                # Sort events by time to check for bursts
                sorted_events = sorted(events, key=lambda x: x['event_time'])
                
                # Check for bursts of 20+ events within 5 minutes
                for i in range(len(sorted_events) - 19):
                    try:
                        start_event_time = datetime.fromisoformat(sorted_events[i]['event_time'].replace('Z', '+00:00'))
                        end_event_time = datetime.fromisoformat(sorted_events[i + 19]['event_time'].replace('Z', '+00:00'))
                        
                        if (end_event_time - start_event_time).total_seconds() < 300:  # 5 minutes
                            suspicious_patterns.append({
                                'type': 'Rapid Enumeration Burst',
                                'username': username,
                                'event_count': 20,
                                'time_window': '5 minutes',
                                'start_time': sorted_events[i]['event_time'],
                                'end_time': sorted_events[i + 19]['event_time'],
                                'risk_reason': f'User {username} performed 20+ enumeration events within 5 minutes'
                            })
                            break  # Only report one burst per user
                    except (ValueError, TypeError):
                        continue
        
        if suspicious_patterns:
            # Create finding for detected enumeration activity
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'CloudTrail',
                'resource_id': f'enumeration-patterns-{region}',
                'status': 'NON_COMPLIANT',
                'compliance_status': 'FAIL',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                'recommendation': COMPLIANCE_DATA.get('recommendation', 'Review and remediate enumeration attempts immediately'),
                'details': {
                    'total_suspicious_patterns': len(suspicious_patterns),
                    'patterns': suspicious_patterns,
                    'detection_timeframe': '24 hours',
                    'monitored_patterns': enumeration_events
                }
            }
        else:
            # No suspicious enumeration patterns detected
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'CloudTrail',
                'resource_id': f'enumeration-monitoring-{region}',
                'status': 'COMPLIANT',
                'compliance_status': 'PASS',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                'recommendation': 'Continue monitoring for enumeration attempts',
                'details': {
                    'total_suspicious_patterns': 0,
                    'detection_timeframe': '24 hours',
                    'monitored_patterns': enumeration_events
                }
            }
        
        findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in cloudtrail_threat_detection_enumeration check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'CloudTrail',
            'resource_id': f'enumeration-check-{region}',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Review and remediate enumeration attempts immediately'),
            'error': str(e)
        })
        
    return findings

def cloudtrail_threat_detection_enumeration(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=cloudtrail_threat_detection_enumeration_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = cloudtrail_threat_detection_enumeration(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

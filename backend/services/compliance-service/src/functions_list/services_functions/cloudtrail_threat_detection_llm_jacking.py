#!/usr/bin/env python3
"""
kisa_isms_p_2023_aws - cloudtrail_threat_detection_llm_jacking

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
                    'recommendation': entry.get('Recommendation', 'Review and remediate LLM jacking attempts immediately')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'kisa_isms_p_2023_aws',
        'function_name': 'cloudtrail_threat_detection_llm_jacking',
        'id': 'KISA-ISMS-P-2023-AWS-LLM-JACK',
        'name': 'CloudTrail LLM Jacking Detection',
        'description': 'To ensure normal use of the information system and prevent misuse (unauthorized access, excessive queries, etc.) by users, log review criteria for access and usage must be established and inspected periodically, and post-event actions must be taken promptly if issues arise.',
        'api_function': 'client = boto3.client(\'cloudtrail\')',
        'user_function': 'lookup_events()',
        'risk_level': 'HIGH',
        'recommendation': 'Review and remediate LLM jacking attempts immediately'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('cloudtrail_threat_detection_llm_jacking')

def cloudtrail_threat_detection_llm_jacking_check(cloudtrail_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform CloudTrail LLM jacking detection check.
    
    Args:
        cloudtrail_client: Boto3 CloudTrail client
        region (str): AWS region
        profile (str): AWS profile name
        logger: Logger instance
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    # LLM/AI service related events that could indicate jacking
    llm_related_events = [
        'InvokeModel',
        'InvokeModelWithResponseStream',
        'CreateModel',
        'CreateEndpoint',
        'InvokeEndpoint',
        'CreateNotebookInstance',
        'StartNotebookInstance',
        'CreateTrainingJob',
        'CreateTransformJob'
    ]
    
    # SageMaker and Bedrock service events
    ai_services = ['sagemaker', 'bedrock']
    
    try:
        # Look for suspicious AI/LLM activity in the last 24 hours
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=24)
        
        suspicious_events = []
        
        # Check for high volume of AI service calls
        for event_name in llm_related_events:
            try:
                response = cloudtrail_client.lookup_events(
                    LookupAttributes=[
                        {
                            'AttributeKey': 'EventName',
                            'AttributeValue': event_name
                        }
                    ],
                    StartTime=start_time,
                    EndTime=end_time
                )
                
                events = response.get('Events', [])
                
                # Flag if more than 100 AI service calls in 24 hours (threshold for suspicious activity)
                if len(events) > 100:
                    for event in events[:10]:  # Sample first 10 events
                        event_time = event.get('EventTime')
                        event_source = event.get('EventSource', 'unknown')
                        username = event.get('Username', 'unknown')
                        source_ip = event.get('SourceIPAddress', 'unknown')
                        
                        suspicious_events.append({
                            'event_name': event_name,
                            'event_time': event_time.isoformat() if event_time else 'unknown',
                            'event_source': event_source,
                            'username': username,
                            'source_ip': source_ip,
                            'aws_region': event.get('AwsRegion', region),
                            'total_occurrences': len(events),
                            'risk_reason': f'High volume of {event_name} calls ({len(events)} in 24h)'
                        })
                    
            except Exception as e:
                logger.warning(f"Error looking up {event_name} events: {e}")
                continue
        
        # Also check for unusual AI service access patterns
        try:
            response = cloudtrail_client.lookup_events(
                LookupAttributes=[
                    {
                        'AttributeKey': 'EventSource',
                        'AttributeValue': 'bedrock.amazonaws.com'
                    }
                ],
                StartTime=start_time,
                EndTime=end_time
            )
            
            bedrock_events = response.get('Events', [])
            unique_ips = set()
            
            for event in bedrock_events:
                source_ip = event.get('SourceIPAddress')
                if source_ip:
                    unique_ips.add(source_ip)
            
            # Flag if Bedrock accessed from more than 10 different IPs in 24 hours
            if len(unique_ips) > 10:
                suspicious_events.append({
                    'event_name': 'Multiple IP Access',
                    'event_time': datetime.utcnow().isoformat(),
                    'event_source': 'bedrock.amazonaws.com',
                    'username': 'multiple',
                    'source_ip': f'{len(unique_ips)} unique IPs',
                    'aws_region': region,
                    'total_occurrences': len(bedrock_events),
                    'risk_reason': f'Bedrock accessed from {len(unique_ips)} different IPs in 24h'
                })
                
        except Exception as e:
            logger.warning(f"Error checking Bedrock access patterns: {e}")
        
        if suspicious_events:
            # Create finding for detected LLM jacking activity
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'CloudTrail',
                'resource_id': f'llm-jacking-events-{region}',
                'status': 'NON_COMPLIANT',
                'compliance_status': 'FAIL',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                'recommendation': COMPLIANCE_DATA.get('recommendation', 'Review and remediate LLM jacking attempts immediately'),
                'details': {
                    'total_suspicious_events': len(suspicious_events),
                    'events': suspicious_events,
                    'detection_timeframe': '24 hours',
                    'monitored_services': ai_services,
                    'monitored_events': llm_related_events
                }
            }
        else:
            # No suspicious LLM activity detected
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'CloudTrail',
                'resource_id': f'llm-jacking-monitoring-{region}',
                'status': 'COMPLIANT',
                'compliance_status': 'PASS',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                'recommendation': 'Continue monitoring for LLM jacking attempts',
                'details': {
                    'total_suspicious_events': 0,
                    'detection_timeframe': '24 hours',
                    'monitored_services': ai_services,
                    'monitored_events': llm_related_events
                }
            }
        
        findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in cloudtrail_threat_detection_llm_jacking check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'CloudTrail',
            'resource_id': f'llm-jacking-check-{region}',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Review and remediate LLM jacking attempts immediately'),
            'error': str(e)
        })
        
    return findings

def cloudtrail_threat_detection_llm_jacking(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=cloudtrail_threat_detection_llm_jacking_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = cloudtrail_threat_detection_llm_jacking(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

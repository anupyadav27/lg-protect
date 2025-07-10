#!/usr/bin/env python3
"""
Compliance check - sns_subscription_not_using_http_endpoints

Checks that SNS subscriptions are not using insecure HTTP endpoints
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
                    'recommendation': entry.get('Recommendation', 'Use HTTPS endpoints instead of HTTP for SNS subscriptions to ensure secure data transmission')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'security_best_practices',
        'function_name': 'sns_subscription_not_using_http_endpoints',
        'id': 'SNS_HTTP_CHECK',
        'name': 'SNS HTTP Endpoint Check',
        'description': 'Checks that SNS subscriptions are not using insecure HTTP endpoints',
        'api_function': 'client=boto3.client(\'sns\')',
        'user_function': 'list_topics(), list_subscriptions_by_topic()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Use HTTPS endpoints instead of HTTP for SNS subscriptions to ensure secure data transmission'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('sns_subscription_not_using_http_endpoints')

def sns_subscription_not_using_http_endpoints_check(sns_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for sns_subscription_not_using_http_endpoints.
    
    Args:
        sns_client: Boto3 SNS client (auto-created by framework)
        region (str): AWS region (auto-managed by framework)
        profile (str): AWS profile name (auto-managed by framework)
        logger: Logger instance (auto-configured by framework)
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    try:
        # Get all topics
        topics_response = sns_client.list_topics()
        topics = topics_response.get('Topics', [])
        
        if not topics:
            logger.info(f"No SNS topics found in region {region}")
            return findings
        
        for topic in topics:
            topic_arn = topic.get('TopicArn', '')
            
            try:
                # Get subscriptions for this topic
                subscriptions_response = sns_client.list_subscriptions_by_topic(TopicArn=topic_arn)
                subscriptions = subscriptions_response.get('Subscriptions', [])
                
                for subscription in subscriptions:
                    subscription_arn = subscription.get('SubscriptionArn', '')
                    protocol = subscription.get('Protocol', '')
                    endpoint = subscription.get('Endpoint', '')
                    
                    # Skip pending confirmations
                    if subscription_arn == 'PendingConfirmation':
                        continue
                    
                    # Check if using HTTP protocol or HTTP endpoint
                    is_using_http = False
                    http_details = {}
                    
                    if protocol == 'http':
                        is_using_http = True
                        http_details['issue'] = 'Protocol is HTTP instead of HTTPS'
                    elif protocol == 'https' and endpoint.startswith('http://'):
                        is_using_http = True
                        http_details['issue'] = 'HTTPS protocol but HTTP endpoint URL'
                    elif endpoint.startswith('http://'):
                        is_using_http = True
                        http_details['issue'] = 'HTTP endpoint URL detected'
                    
                    finding = {
                        'region': region,
                        'profile': profile,
                        'resource_type': 'SNSSubscription',
                        'resource_id': subscription_arn,
                        'status': 'NON_COMPLIANT' if is_using_http else 'COMPLIANT',
                        'compliance_status': 'FAIL' if is_using_http else 'PASS',
                        'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                        'recommendation': COMPLIANCE_DATA.get('recommendation', 'Use HTTPS endpoints instead of HTTP for SNS subscriptions'),
                        'details': {
                            'topic_arn': topic_arn,
                            'subscription_arn': subscription_arn,
                            'protocol': protocol,
                            'endpoint': endpoint,
                            'is_using_http': is_using_http,
                            **http_details
                        }
                    }
                    
                    findings.append(finding)
                    
                    if is_using_http:
                        logger.warning(f"SNS subscription {subscription_arn} is using insecure HTTP endpoint")
                    else:
                        logger.info(f"SNS subscription {subscription_arn} is using secure endpoint")
                        
            except Exception as topic_error:
                logger.error(f"Error checking subscriptions for topic {topic_arn}: {topic_error}")
                findings.append({
                    'region': region,
                    'profile': profile,
                    'resource_type': 'SNSTopic',
                    'resource_id': topic_arn,
                    'status': 'ERROR',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Use HTTPS endpoints instead of HTTP for SNS subscriptions'),
                    'error': str(topic_error)
                })
        
    except Exception as e:
        logger.error(f"Error in sns_subscription_not_using_http_endpoints check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'SNSSubscription',
            'status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Use HTTPS endpoints instead of HTTP for SNS subscriptions'),
            'error': str(e)
        })
        
    return findings

def sns_subscription_not_using_http_endpoints(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=sns_subscription_not_using_http_endpoints_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = sns_subscription_not_using_http_endpoints(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

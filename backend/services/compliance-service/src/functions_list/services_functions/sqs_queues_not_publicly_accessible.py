#!/usr/bin/env python3
"""
Compliance check - sqs_queues_not_publicly_accessible

Checks that SQS queues are not publicly accessible
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
                    'risk_level': entry.get('Risk Level', 'HIGH'),
                    'recommendation': entry.get('Recommendation', 'Remove public access from SQS queues and restrict access to authorized principals only')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'security_best_practices',
        'function_name': 'sqs_queues_not_publicly_accessible',
        'id': 'SQS_PUBLIC_ACCESS',
        'name': 'SQS Public Access Check',
        'description': 'Checks that SQS queues are not publicly accessible',
        'api_function': 'client=boto3.client(\'sqs\')',
        'user_function': 'list_queues(), get_queue_attributes()',
        'risk_level': 'HIGH',
        'recommendation': 'Remove public access from SQS queues and restrict access to authorized principals only'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('sqs_queues_not_publicly_accessible')

def sqs_queues_not_publicly_accessible_check(sqs_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for sqs_queues_not_publicly_accessible.
    
    Args:
        sqs_client: Boto3 SQS client (auto-created by framework)
        region (str): AWS region (auto-managed by framework)
        profile (str): AWS profile name (auto-managed by framework)
        logger: Logger instance (auto-configured by framework)
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    try:
        # Get all queues
        queues_response = sqs_client.list_queues()
        queue_urls = queues_response.get('QueueUrls', [])
        
        if not queue_urls:
            logger.info(f"No SQS queues found in region {region}")
            return findings
        
        for queue_url in queue_urls:
            queue_name = queue_url.split('/')[-1] if queue_url else 'Unknown'
            
            try:
                # Get queue attributes to check policy
                attributes_response = sqs_client.get_queue_attributes(
                    QueueUrl=queue_url,
                    AttributeNames=['All']
                )
                attributes = attributes_response.get('Attributes', {})
                
                # Check queue policy for public access
                policy_json = attributes.get('Policy')
                is_publicly_accessible = False
                public_access_details = []
                
                if policy_json:
                    try:
                        import json as json_lib
                        policy = json_lib.loads(policy_json)
                        statements = policy.get('Statement', [])
                        
                        if not isinstance(statements, list):
                            statements = [statements]
                        
                        for statement in statements:
                            principal = statement.get('Principal')
                            effect = statement.get('Effect', '')
                            
                            # Check for wildcard principals indicating public access
                            if effect.upper() == 'ALLOW':
                                if principal == '*':
                                    is_publicly_accessible = True
                                    public_access_details.append('Wildcard principal (*) allowed')
                                elif isinstance(principal, dict):
                                    aws_principals = principal.get('AWS', [])
                                    if isinstance(aws_principals, str):
                                        aws_principals = [aws_principals]
                                    if '*' in aws_principals:
                                        is_publicly_accessible = True
                                        public_access_details.append('Wildcard AWS principal (*) allowed')
                                elif isinstance(principal, str) and principal == '*':
                                    is_publicly_accessible = True
                                    public_access_details.append('Wildcard principal string (*) allowed')
                    
                    except json_lib.JSONDecodeError as json_error:
                        logger.warning(f"Could not parse policy JSON for queue {queue_url}: {json_error}")
                        public_access_details.append(f"Policy parsing error: {json_error}")
                
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'SQSQueue',
                    'resource_id': queue_url,
                    'status': 'NON_COMPLIANT' if is_publicly_accessible else 'COMPLIANT',
                    'compliance_status': 'FAIL' if is_publicly_accessible else 'PASS',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Remove public access from SQS queues'),
                    'details': {
                        'queue_url': queue_url,
                        'queue_name': queue_name,
                        'is_publicly_accessible': is_publicly_accessible,
                        'public_access_details': public_access_details,
                        'has_policy': bool(policy_json),
                        'queue_arn': attributes.get('QueueArn', ''),
                        'visibility_timeout': attributes.get('VisibilityTimeout', ''),
                        'message_retention_period': attributes.get('MessageRetentionPeriod', ''),
                        'is_fifo_queue': queue_name.endswith('.fifo')
                    }
                }
                
                findings.append(finding)
                
                if is_publicly_accessible:
                    logger.warning(f"SQS queue {queue_name} is publicly accessible: {public_access_details}")
                else:
                    logger.info(f"SQS queue {queue_name} is not publicly accessible")
                    
            except Exception as queue_error:
                logger.error(f"Error checking public access for queue {queue_url}: {queue_error}")
                findings.append({
                    'region': region,
                    'profile': profile,
                    'resource_type': 'SQSQueue',
                    'resource_id': queue_url,
                    'status': 'ERROR',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Remove public access from SQS queues'),
                    'error': str(queue_error)
                })
        
    except Exception as e:
        logger.error(f"Error in sqs_queues_not_publicly_accessible check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'SQSQueue',
            'status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Remove public access from SQS queues'),
            'error': str(e)
        })
        
    return findings

def sqs_queues_not_publicly_accessible(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=sqs_queues_not_publicly_accessible_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = sqs_queues_not_publicly_accessible(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

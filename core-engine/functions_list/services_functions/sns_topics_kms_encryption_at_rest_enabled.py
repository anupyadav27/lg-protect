#!/usr/bin/env python3
"""
Compliance check - sns_topics_kms_encryption_at_rest_enabled

Checks that SNS topics have KMS encryption at rest enabled
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
                    'recommendation': entry.get('Recommendation', 'Enable KMS encryption at rest for SNS topics to protect sensitive data')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'security_best_practices',
        'function_name': 'sns_topics_kms_encryption_at_rest_enabled',
        'id': 'SNS_KMS_ENCRYPTION',
        'name': 'SNS KMS Encryption Check',
        'description': 'Checks that SNS topics have KMS encryption at rest enabled',
        'api_function': 'client=boto3.client(\'sns\')',
        'user_function': 'list_topics(), get_topic_attributes()',
        'risk_level': 'HIGH',
        'recommendation': 'Enable KMS encryption at rest for SNS topics to protect sensitive data'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('sns_topics_kms_encryption_at_rest_enabled')

def sns_topics_kms_encryption_at_rest_enabled_check(sns_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for sns_topics_kms_encryption_at_rest_enabled.
    
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
            topic_name = topic_arn.split(':')[-1] if topic_arn else 'Unknown'
            
            try:
                # Get topic attributes to check encryption settings
                attributes_response = sns_client.get_topic_attributes(TopicArn=topic_arn)
                attributes = attributes_response.get('Attributes', {})
                
                # Check for KMS encryption
                kms_master_key_id = attributes.get('KmsMasterKeyId')
                is_encrypted = bool(kms_master_key_id)
                
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'SNSTopic',
                    'resource_id': topic_arn,
                    'status': 'COMPLIANT' if is_encrypted else 'NON_COMPLIANT',
                    'compliance_status': 'PASS' if is_encrypted else 'FAIL',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable KMS encryption at rest for SNS topics'),
                    'details': {
                        'topic_arn': topic_arn,
                        'topic_name': topic_name,
                        'kms_encryption_enabled': is_encrypted,
                        'kms_master_key_id': kms_master_key_id,
                        'owner': attributes.get('Owner', ''),
                        'subscriptions_confirmed': int(attributes.get('SubscriptionsConfirmed', 0)),
                        'subscriptions_pending': int(attributes.get('SubscriptionsPending', 0))
                    }
                }
                
                findings.append(finding)
                
                if is_encrypted:
                    logger.info(f"SNS topic {topic_name} has KMS encryption enabled with key: {kms_master_key_id}")
                else:
                    logger.warning(f"SNS topic {topic_name} does not have KMS encryption enabled")
                    
            except Exception as topic_error:
                logger.error(f"Error checking encryption for topic {topic_arn}: {topic_error}")
                findings.append({
                    'region': region,
                    'profile': profile,
                    'resource_type': 'SNSTopic',
                    'resource_id': topic_arn,
                    'status': 'ERROR',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable KMS encryption at rest for SNS topics'),
                    'error': str(topic_error)
                })
        
    except Exception as e:
        logger.error(f"Error in sns_topics_kms_encryption_at_rest_enabled check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'SNSTopic',
            'status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable KMS encryption at rest for SNS topics'),
            'error': str(e)
        })
        
    return findings

def sns_topics_kms_encryption_at_rest_enabled(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=sns_topics_kms_encryption_at_rest_enabled_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = sns_topics_kms_encryption_at_rest_enabled(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

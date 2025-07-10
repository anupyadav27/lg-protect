#!/usr/bin/env python3
"""
iso27001_2022_aws - bedrock_model_invocation_logging_enabled

Logs that record activities, exceptions, faults and other relevant events should be produced, stored, protected and analysed.
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
        compliance_json_path = os.path.join(
            os.path.dirname(__file__), '..', '..', 'compliance_checks.json'
        )
        
        with open(compliance_json_path, 'r') as f:
            compliance_data = json.load(f)
        
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
        
    return {
        'compliance_name': 'iso27001_2022_aws',
        'function_name': 'bedrock_model_invocation_logging_enabled',
        'id': 'BR.1',
        'name': 'Bedrock model invocation logging should be enabled',
        'description': 'Logs that record activities, exceptions, faults and other relevant events should be produced, stored, protected and analysed.',
        'api_function': 'client = boto3.client("bedrock")',
        'user_function': 'get_model_invocation_logging_configuration()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Enable model invocation logging for Amazon Bedrock to monitor AI/ML model usage and security events'
    }

COMPLIANCE_DATA = load_compliance_metadata('bedrock_model_invocation_logging_enabled')

def bedrock_model_invocation_logging_enabled_check(bedrock_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for bedrock_model_invocation_logging_enabled.
    """
    findings = []
    
    try:
        # Check if Bedrock service is available in this region
        try:
            # Get model invocation logging configuration
            response = bedrock_client.get_model_invocation_logging_configuration()
            logging_config = response.get('loggingConfig', {})
            
            # Check if logging is enabled
            embedding_data_delivery_enabled = logging_config.get('embeddingDataDeliveryEnabled', False)
            image_data_delivery_enabled = logging_config.get('imageDataDeliveryEnabled', False)
            text_data_delivery_enabled = logging_config.get('textDataDeliveryEnabled', False)
            
            # Check CloudWatch configuration
            cloudwatch_config = logging_config.get('cloudWatchConfig', {})
            cloudwatch_enabled = bool(cloudwatch_config.get('logGroupName'))
            
            # Check S3 configuration
            s3_config = logging_config.get('s3Config', {})
            s3_enabled = bool(s3_config.get('bucketName'))
            
            # Determine if any logging is enabled
            any_logging_enabled = (
                embedding_data_delivery_enabled or 
                image_data_delivery_enabled or 
                text_data_delivery_enabled or
                cloudwatch_enabled or 
                s3_enabled
            )
            
            status = 'COMPLIANT' if any_logging_enabled else 'NON_COMPLIANT'
            compliance_status = 'PASS' if any_logging_enabled else 'FAIL'
            
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'BEDROCK_LOGGING',
                'resource_id': f'BEDROCK_LOGGING_{region}',
                'status': status,
                'compliance_status': compliance_status,
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable model invocation logging for Amazon Bedrock to monitor AI/ML model usage and security events'),
                'details': {
                    'region': region,
                    'logging_enabled': any_logging_enabled,
                    'embedding_data_delivery_enabled': embedding_data_delivery_enabled,
                    'image_data_delivery_enabled': image_data_delivery_enabled,
                    'text_data_delivery_enabled': text_data_delivery_enabled,
                    'cloudwatch_logging': {
                        'enabled': cloudwatch_enabled,
                        'log_group_name': cloudwatch_config.get('logGroupName'),
                        'role_arn': cloudwatch_config.get('roleArn')
                    },
                    's3_logging': {
                        'enabled': s3_enabled,
                        'bucket_name': s3_config.get('bucketName'),
                        'key_prefix': s3_config.get('keyPrefix')
                    },
                    'large_data_delivery_s3_config': logging_config.get('largeDataDeliveryS3Config', {})
                }
            }
            
        except bedrock_client.exceptions.ValidationException as ve:
            # Handle case where logging configuration doesn't exist or is invalid
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'BEDROCK_LOGGING',
                'resource_id': f'BEDROCK_LOGGING_{region}',
                'status': 'NON_COMPLIANT',
                'compliance_status': 'FAIL',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable model invocation logging for Amazon Bedrock to monitor AI/ML model usage and security events'),
                'details': {
                    'region': region,
                    'logging_enabled': False,
                    'issue': 'No model invocation logging configuration found',
                    'validation_error': str(ve),
                    'remediation_steps': [
                        'Navigate to Amazon Bedrock console',
                        'Go to Settings > Model invocation logging',
                        'Enable logging for model invocations',
                        'Configure CloudWatch Logs destination for real-time monitoring',
                        'Configure S3 destination for long-term storage',
                        'Enable logging for embedding, image, and text data as needed',
                        'Set up appropriate IAM roles and permissions',
                        'Test logging configuration with sample model invocations'
                    ]
                }
            }
            
        except Exception as config_error:
            if 'AccessDeniedException' in str(config_error):
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'BEDROCK_LOGGING',
                    'resource_id': f'BEDROCK_LOGGING_{region}',
                    'status': 'ERROR',
                    'compliance_status': 'ERROR',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                    'recommendation': 'Ensure proper IAM permissions to access Bedrock logging configuration',
                    'details': {
                        'region': region,
                        'error': str(config_error),
                        'reason': 'Access denied - insufficient permissions to check Bedrock logging configuration'
                    }
                }
            elif 'ServiceUnavailableException' in str(config_error) or 'bedrock is not available' in str(config_error).lower():
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'BEDROCK_LOGGING',
                    'resource_id': f'BEDROCK_LOGGING_{region}',
                    'status': 'NOT_APPLICABLE',
                    'compliance_status': 'PASS',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                    'recommendation': 'Bedrock service is not available in this region',
                    'details': {
                        'region': region,
                        'message': 'Bedrock service is not available in this region',
                        'service_availability': False
                    }
                }
            else:
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'BEDROCK_LOGGING',
                    'resource_id': f'BEDROCK_LOGGING_{region}',
                    'status': 'ERROR',
                    'compliance_status': 'ERROR',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable model invocation logging for Amazon Bedrock to monitor AI/ML model usage and security events'),
                    'details': {
                        'region': region,
                        'error': str(config_error),
                        'reason': 'Could not retrieve Bedrock logging configuration'
                    }
                }
        
        findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in bedrock_model_invocation_logging_enabled check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'BEDROCK_LOGGING',
            'status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable model invocation logging for Amazon Bedrock to monitor AI/ML model usage and security events'),
            'error': str(e)
        })
        
    return findings

def bedrock_model_invocation_logging_enabled(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=bedrock_model_invocation_logging_enabled_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    args = setup_command_line_interface(COMPLIANCE_DATA)
    results = bedrock_model_invocation_logging_enabled(
        profile_name=args.profile,
        region_name=args.region
    )
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

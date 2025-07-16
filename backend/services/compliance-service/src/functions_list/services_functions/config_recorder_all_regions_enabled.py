#!/usr/bin/env python3
"""
cis_4.0_aws - config_recorder_all_regions_enabled

Ensure AWS Config is enabled in all regions
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
        'compliance_name': 'cis_4.0_aws',
        'function_name': 'config_recorder_all_regions_enabled',
        'id': '3.5',
        'name': 'Ensure AWS Config is enabled in all regions',
        'description': 'Ensure AWS Config is enabled in all regions',
        'api_function': 'client = boto3.client("config")',
        'user_function': 'describe_configuration_recorders(), describe_configuration_recorder_status(), describe_delivery_channels()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Enable AWS Config service in all regions to track configuration changes'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('config_recorder_all_regions_enabled')

def config_recorder_all_regions_enabled_check(config_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for config_recorder_all_regions_enabled.
    
    Args:
        config_client: Boto3 Config client (auto-created by framework)
        region (str): AWS region (auto-managed by framework)
        profile (str): AWS profile name (auto-managed by framework)
        logger: Logger instance (auto-configured by framework)
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    try:
        logger.info(f"Checking AWS Config recorder status in region {region}")
        
        # Get configuration recorders
        recorders_response = config_client.describe_configuration_recorders()
        recorders = recorders_response.get('ConfigurationRecorders', [])
        
        # Get configuration recorder status
        try:
            status_response = config_client.describe_configuration_recorder_status()
            recorder_statuses = status_response.get('ConfigurationRecordersStatus', [])
        except Exception as e:
            logger.warning(f"Could not get recorder status in {region}: {e}")
            recorder_statuses = []
        
        # Get delivery channels
        try:
            delivery_response = config_client.describe_delivery_channels()
            delivery_channels = delivery_response.get('DeliveryChannels', [])
        except Exception as e:
            logger.warning(f"Could not get delivery channels in {region}: {e}")
            delivery_channels = []
        
        if not recorders:
            # No configuration recorders found
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'AWS Config Recorder',
                'resource_id': 'no-recorder-found',
                'status': 'NON_COMPLIANT',
                'compliance_status': 'FAIL',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                'recommendation': COMPLIANCE_DATA.get('recommendation', 'Create and enable AWS Config recorder'),
                'details': {
                    'issue': 'No AWS Config configuration recorder found in this region',
                    'recorders_count': 0,
                    'delivery_channels_count': len(delivery_channels),
                    'security_risk': 'Without Config, configuration changes are not tracked or monitored',
                    'remediation_steps': [
                        'Navigate to AWS Config console',
                        'Set up configuration recorder',
                        'Configure delivery channel (S3 bucket)',
                        'Enable recording for all resource types',
                        'Start the configuration recorder'
                    ]
                }
            }
            findings.append(finding)
            return findings
        
        # Check each recorder
        for recorder in recorders:
            recorder_name = recorder.get('name', 'unknown')
            role_arn = recorder.get('roleARN', 'unknown')
            recording_group = recorder.get('recordingGroup', {})
            
            # Find corresponding status
            recorder_status = None
            for status in recorder_statuses:
                if status.get('name') == recorder_name:
                    recorder_status = status
                    break
            
            is_recording = recorder_status.get('recording', False) if recorder_status else False
            last_start_time = recorder_status.get('lastStartTime', '') if recorder_status else ''
            last_status = recorder_status.get('lastStatus', 'UNKNOWN') if recorder_status else 'UNKNOWN'
            
            # Check recording group configuration
            all_supported = recording_group.get('allSupported', False)
            include_global_types = recording_group.get('includeGlobalResourceTypes', False)
            resource_types = recording_group.get('resourceTypes', [])
            
            # Check if delivery channel exists and is properly configured
            has_delivery_channel = len(delivery_channels) > 0
            
            if is_recording and has_delivery_channel and last_status == 'SUCCESS':
                # Compliant: Config recorder is active and properly configured
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'AWS Config Recorder',
                    'resource_id': recorder_name,
                    'status': 'COMPLIANT',
                    'compliance_status': 'PASS',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'AWS Config is properly enabled'),
                    'details': {
                        'recorder_name': recorder_name,
                        'role_arn': role_arn,
                        'is_recording': is_recording,
                        'last_status': last_status,
                        'last_start_time': last_start_time.isoformat() if last_start_time else '',
                        'recording_group': {
                            'all_supported': all_supported,
                            'include_global_types': include_global_types,
                            'resource_types_count': len(resource_types)
                        },
                        'delivery_channels_count': len(delivery_channels),
                        'delivery_channels': [
                            {
                                'name': dc.get('name', ''),
                                's3_bucket_name': dc.get('s3BucketName', ''),
                                's3_key_prefix': dc.get('s3KeyPrefix', ''),
                                'sns_topic_arn': dc.get('snsTopicARN', '')
                            }
                            for dc in delivery_channels
                        ]
                    }
                }
            else:
                # Non-compliant: Config recorder exists but is not properly configured or active
                issues = []
                if not is_recording:
                    issues.append('Configuration recorder is not recording')
                if not has_delivery_channel:
                    issues.append('No delivery channel configured')
                if last_status != 'SUCCESS':
                    issues.append(f'Last recording status was {last_status}')
                
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'AWS Config Recorder',
                    'resource_id': recorder_name,
                    'status': 'NON_COMPLIANT',
                    'compliance_status': 'FAIL',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Fix AWS Config recorder configuration'),
                    'details': {
                        'recorder_name': recorder_name,
                        'role_arn': role_arn,
                        'is_recording': is_recording,
                        'last_status': last_status,
                        'last_start_time': last_start_time.isoformat() if last_start_time else '',
                        'issues': issues,
                        'recording_group': {
                            'all_supported': all_supported,
                            'include_global_types': include_global_types,
                            'resource_types_count': len(resource_types)
                        },
                        'delivery_channels_count': len(delivery_channels),
                        'security_risk': 'Configuration changes may not be properly tracked',
                        'remediation_steps': [
                            'Check IAM role permissions for Config service',
                            'Ensure delivery channel is properly configured',
                            'Start the configuration recorder if stopped',
                            'Verify S3 bucket permissions for delivery channel'
                        ]
                    }
                }
            
            findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in config_recorder_all_regions_enabled check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'AWS Config Recorder',
            'status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Review and remediate as needed'),
            'error': str(e)
        })
        
    return findings

def config_recorder_all_regions_enabled(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=config_recorder_all_regions_enabled_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = config_recorder_all_regions_enabled(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

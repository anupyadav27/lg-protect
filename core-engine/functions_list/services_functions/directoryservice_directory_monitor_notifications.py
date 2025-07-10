#!/usr/bin/env python3
"""
kisa_isms_p_2023_aws - directoryservice_directory_monitor_notifications

To ensure the availability of information systems, performance and capacity requirements must be defined, and the status must be continuously monitored.
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
                    'recommendation': entry.get('Recommendation', 'Configure monitoring and notifications for Directory Service')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'kisa_isms_p_2023_aws',
        'function_name': 'directoryservice_directory_monitor_notifications',
        'id': '2.9.2',
        'name': 'Performance and Fault Management',
        'description': 'To ensure the availability of information systems, performance and capacity requirements must be defined, and the status must be continuously monitored.',
        'api_function': 'client=boto3.client(\'ds\')',
        'user_function': 'describe_directories()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Configure monitoring and notifications for Directory Service'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('directoryservice_directory_monitor_notifications')

def directoryservice_directory_monitor_notifications_check(ds_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for directoryservice_directory_monitor_notifications.
    
    Args:
        ds_client: Boto3 Directory Service client (auto-created by framework)
        region (str): AWS region (auto-managed by framework)
        profile (str): AWS profile name (auto-managed by framework)
        logger: Logger instance (auto-configured by framework)
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    try:
        # Get all directories
        response = ds_client.describe_directories()
        directories = response.get('DirectoryDescriptions', [])
        
        if not directories:
            # No directories found
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'DirectoryService',
                'resource_id': f'ds-check-{region}',
                'status': 'COMPLIANT',
                'compliance_status': 'PASS',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                'recommendation': 'No Directory Service directories found',
                'details': {
                    'total_directories': 0
                }
            }
            findings.append(finding)
            return findings
        
        # Check each directory for monitoring configuration
        for directory in directories:
            directory_id = directory.get('DirectoryId', '')
            directory_name = directory.get('Name', 'unknown')
            directory_type = directory.get('Type', 'unknown')
            directory_stage = directory.get('Stage', 'unknown')
            
            # Check if directory is active
            if directory_stage != 'Active':
                continue
            
            try:
                # Check for CloudWatch log groups and event notifications
                # Directory Service can publish logs to CloudWatch
                log_subscriptions = []
                
                try:
                    # Get log subscriptions for this directory
                    log_response = ds_client.list_log_subscriptions(DirectoryId=directory_id)
                    log_subscriptions = log_response.get('LogSubscriptions', [])
                except Exception as e:
                    logger.warning(f"Could not retrieve log subscriptions for directory {directory_id}: {e}")
                
                # Check for SNS topics or CloudWatch alarms (would need additional clients)
                # For this check, we'll focus on log subscriptions as the primary monitoring mechanism
                
                monitoring_enabled = len(log_subscriptions) > 0
                
                if monitoring_enabled:
                    status = 'COMPLIANT'
                    compliance_status = 'PASS'
                    recommendation = 'Directory Service has monitoring configured'
                else:
                    status = 'NON_COMPLIANT'
                    compliance_status = 'FAIL'
                    recommendation = 'Configure CloudWatch logging and monitoring for Directory Service'
                
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'DirectoryService Directory',
                    'resource_id': directory_id,
                    'status': status,
                    'compliance_status': compliance_status,
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                    'recommendation': recommendation,
                    'details': {
                        'directory_id': directory_id,
                        'directory_name': directory_name,
                        'directory_type': directory_type,
                        'directory_stage': directory_stage,
                        'monitoring_enabled': monitoring_enabled,
                        'log_subscriptions_count': len(log_subscriptions),
                        'log_subscriptions': log_subscriptions,
                        'dns_ip_addrs': directory.get('DnsIpAddrs', []),
                        'vpc_settings': directory.get('VpcSettings', {})
                    }
                }
                
                findings.append(finding)
                
            except Exception as e:
                logger.warning(f"Error checking monitoring for directory {directory_id}: {e}")
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'DirectoryService Directory',
                    'resource_id': directory_id,
                    'status': 'ERROR',
                    'compliance_status': 'ERROR',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                    'recommendation': 'Unable to check monitoring configuration due to access error',
                    'error': str(e),
                    'details': {
                        'directory_id': directory_id,
                        'directory_name': directory_name,
                        'directory_type': directory_type
                    }
                }
                findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in directoryservice_directory_monitor_notifications check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'DirectoryService',
            'resource_id': f'ds-error-{region}',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Configure monitoring and notifications for Directory Service'),
            'error': str(e)
        })
        
    return findings

def directoryservice_directory_monitor_notifications(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=directoryservice_directory_monitor_notifications_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = directoryservice_directory_monitor_notifications(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

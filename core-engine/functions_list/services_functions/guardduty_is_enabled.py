#!/usr/bin/env python3
"""
fedramp_low_revision_4_aws - guardduty_is_enabled

The information system protects against or limits the effects of the following types of denial of service attacks: [Assignment: organization-defined types of denial of service attacks or references to sources for such information] by employing [Assignment: organization-defined security safeguards].
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
        'compliance_name': 'fedramp_low_revision_4_aws',
        'function_name': 'guardduty_is_enabled',
        'id': 'SC-5',
        'name': 'Ensure GuardDuty is enabled',
        'description': 'The information system protects against or limits the effects of denial of service attacks',
        'api_function': 'client = boto3.client("guardduty")',
        'user_function': 'list_detectors()',
        'risk_level': 'HIGH',
        'recommendation': 'Enable GuardDuty threat detection service to protect against malicious activity'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('guardduty_is_enabled')

def guardduty_is_enabled_check(guardduty_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for guardduty_is_enabled.
    
    Args:
        guardduty_client: Boto3 GuardDuty client (auto-created by framework)
        region (str): AWS region (auto-managed by framework)
        profile (str): AWS profile name (auto-managed by framework)
        logger: Logger instance (auto-configured by framework)
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    try:
        logger.info(f"Checking GuardDuty status in region {region}")
        
        # Get all GuardDuty detectors
        detectors_response = guardduty_client.list_detectors()
        detector_ids = detectors_response.get('DetectorIds', [])
        
        if not detector_ids:
            # No detectors found - GuardDuty is not enabled
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'GuardDuty Detector',
                'resource_id': 'no-detector-found',
                'status': 'NON_COMPLIANT',
                'compliance_status': 'FAIL',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable GuardDuty threat detection service'),
                'details': {
                    'issue': 'GuardDuty is not enabled in this region',
                    'detectors_count': 0,
                    'security_risk': 'Without GuardDuty, malicious activity and threats may go undetected',
                    'remediation_steps': [
                        'Navigate to GuardDuty console',
                        'Click "Get started"',
                        'Enable GuardDuty for the region',
                        'Configure threat intelligence and malware scanning',
                        'Set up CloudWatch Events for alerts'
                    ]
                }
            }
            findings.append(finding)
            return findings
        
        # Check each detector's status
        for detector_id in detector_ids:
            try:
                # Get detector details
                detector_details = guardduty_client.get_detector(DetectorId=detector_id)
                
                status = detector_details.get('Status', 'DISABLED')
                service_role = detector_details.get('ServiceRole', 'unknown')
                created_at = detector_details.get('CreatedAt', '')
                updated_at = detector_details.get('UpdatedAt', '')
                
                # Get additional detector configuration
                finding_publishing_frequency = detector_details.get('FindingPublishingFrequency', 'SIX_HOURS')
                
                # Check data sources configuration
                data_sources = detector_details.get('DataSources', {})
                s3_logs = data_sources.get('S3Logs', {}).get('Status', 'DISABLED')
                kubernetes = data_sources.get('Kubernetes', {}).get('Status', 'DISABLED')
                malware_protection = data_sources.get('MalwareProtection', {}).get('Status', 'DISABLED')
                
                if status == 'ENABLED':
                    # Compliant: GuardDuty detector is enabled
                    finding = {
                        'region': region,
                        'profile': profile,
                        'resource_type': 'GuardDuty Detector',
                        'resource_id': detector_id,
                        'status': 'COMPLIANT',
                        'compliance_status': 'PASS',
                        'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                        'recommendation': COMPLIANCE_DATA.get('recommendation', 'GuardDuty is properly enabled'),
                        'details': {
                            'detector_id': detector_id,
                            'status': status,
                            'service_role': service_role,
                            'finding_publishing_frequency': finding_publishing_frequency,
                            'created_at': created_at.isoformat() if created_at else '',
                            'updated_at': updated_at.isoformat() if updated_at else '',
                            'data_sources': {
                                's3_logs': s3_logs,
                                'kubernetes': kubernetes,
                                'malware_protection': malware_protection
                            }
                        }
                    }
                else:
                    # Non-compliant: GuardDuty detector exists but is disabled
                    finding = {
                        'region': region,
                        'profile': profile,
                        'resource_type': 'GuardDuty Detector',
                        'resource_id': detector_id,
                        'status': 'NON_COMPLIANT',
                        'compliance_status': 'FAIL',
                        'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                        'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable the GuardDuty detector'),
                        'details': {
                            'detector_id': detector_id,
                            'status': status,
                            'issue': f'GuardDuty detector exists but is {status.lower()}',
                            'service_role': service_role,
                            'finding_publishing_frequency': finding_publishing_frequency,
                            'created_at': created_at.isoformat() if created_at else '',
                            'updated_at': updated_at.isoformat() if updated_at else '',
                            'security_risk': 'Disabled GuardDuty detector provides no threat protection',
                            'remediation_steps': [
                                'Navigate to GuardDuty console',
                                'Select the detector',
                                'Enable the detector',
                                'Verify data sources are configured properly'
                            ]
                        }
                    }
                
                findings.append(finding)
                
            except Exception as e:
                logger.error(f"Error checking GuardDuty detector {detector_id} in {region}: {e}")
                findings.append({
                    'region': region,
                    'profile': profile,
                    'resource_type': 'GuardDuty Detector',
                    'resource_id': detector_id,
                    'status': 'ERROR',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Review detector configuration'),
                    'error': str(e)
                })
        
    except Exception as e:
        logger.error(f"Error in guardduty_is_enabled check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'GuardDuty Detector',
            'status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Review and remediate as needed'),
            'error': str(e)
        })
        
    return findings

def guardduty_is_enabled(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=guardduty_is_enabled_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = guardduty_is_enabled(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

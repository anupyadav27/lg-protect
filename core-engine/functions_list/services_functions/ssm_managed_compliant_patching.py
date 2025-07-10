#!/usr/bin/env python3
"""
fedramp_low_revision_4_aws - ssm_managed_compliant_patching

The organization develops and documents an inventory of information system components that accurately reflects the current information system, includes all components within the authorization boundary of the information system, is at the level of granularity deemed necessary for tracking and reporting and reviews and updates the information system component inventory.
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
        'compliance_name': 'fedramp_low_revision_4_aws',
        'function_name': 'ssm_managed_compliant_patching',
        'id': 'CM-8',
        'name': 'SSM managed compliant patching',
        'description': 'The organization develops and documents an inventory of information system components',
        'api_function': 'client = boto3.client("ssm")',
        'user_function': 'describe_instance_patch_states()',
        'risk_level': 'HIGH',
        'recommendation': 'Ensure instances are compliant with patch baselines'
    }

COMPLIANCE_DATA = load_compliance_metadata('ssm_managed_compliant_patching')

def ssm_managed_compliant_patching_check(ssm_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for ssm_managed_compliant_patching.
    """
    findings = []
    
    try:
        # Get all SSM managed instances
        instances_response = ssm_client.describe_instance_information()
        instances = instances_response.get('InstanceInformationList', [])
        
        for instance in instances:
            instance_id = instance.get('InstanceId')
            
            try:
                # Get patch compliance status for the instance
                patch_response = ssm_client.describe_instance_patch_states(
                    InstanceIds=[instance_id]
                )
                patch_states = patch_response.get('InstancePatchStates', [])
                
                for patch_state in patch_states:
                    # Check patch compliance metrics
                    installed_count = patch_state.get('InstalledCount', 0)
                    missing_count = patch_state.get('MissingCount', 0)
                    failed_count = patch_state.get('FailedCount', 0)
                    operation = patch_state.get('Operation', '')
                    operation_end_time = patch_state.get('OperationEndTime')
                    
                    # Determine compliance status
                    is_compliant = missing_count == 0 and failed_count == 0
                    
                    status = 'COMPLIANT' if is_compliant else 'NON_COMPLIANT'
                    compliance_status = 'PASS' if is_compliant else 'FAIL'
                    
                    finding = {
                        'region': region,
                        'profile': profile,
                        'resource_type': 'EC2_INSTANCE',
                        'resource_id': instance_id,
                        'status': status,
                        'compliance_status': compliance_status,
                        'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                        'recommendation': COMPLIANCE_DATA.get('recommendation', 'Ensure instances are compliant with patch baselines'),
                        'details': {
                            'instance_id': instance_id,
                            'installed_patches': installed_count,
                            'missing_patches': missing_count,
                            'failed_patches': failed_count,
                            'last_operation': operation,
                            'last_operation_time': str(operation_end_time) if operation_end_time else None,
                            'is_compliant': is_compliant
                        }
                    }
                    
                    findings.append(finding)
                    
            except Exception as instance_error:
                logger.warning(f"Could not check patch state for instance {instance_id}: {instance_error}")
                # Create error finding for this instance
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'EC2_INSTANCE',
                    'resource_id': instance_id,
                    'status': 'ERROR',
                    'compliance_status': 'ERROR',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Ensure instances are compliant with patch baselines'),
                    'details': {
                        'instance_id': instance_id,
                        'error': str(instance_error)
                    }
                }
                findings.append(finding)
        
        # If no instances found, add informational finding
        if not instances:
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'SSM_INSTANCES',
                'resource_id': 'NO_INSTANCES',
                'status': 'COMPLIANT',
                'compliance_status': 'PASS',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                'recommendation': 'No SSM managed instances found in this region',
                'details': {
                    'message': 'No SSM managed instances found',
                    'instances_count': 0
                }
            }
            findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in ssm_managed_compliant_patching check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'SSM_INSTANCES',
            'status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Ensure instances are compliant with patch baselines'),
            'error': str(e)
        })
        
    return findings

def ssm_managed_compliant_patching(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=ssm_managed_compliant_patching_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    args = setup_command_line_interface(COMPLIANCE_DATA)
    results = ssm_managed_compliant_patching(
        profile_name=args.profile,
        region_name=args.region
    )
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

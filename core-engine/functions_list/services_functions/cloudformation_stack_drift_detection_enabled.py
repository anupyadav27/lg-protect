#!/usr/bin/env python3
"""
aws_foundational_security_best_practices_aws - cloudformation_stack_drift_detection_enabled

CloudFormation stacks should have drift detection enabled
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
    """Load compliance metadata from compliance_checks.json."""
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
        'compliance_name': 'aws_foundational_security_best_practices_aws',
        'function_name': 'cloudformation_stack_drift_detection_enabled',
        'id': 'CloudFormation.1',
        'name': 'CloudFormation stacks should have drift detection enabled',
        'description': 'CloudFormation stacks should have drift detection enabled',
        'api_function': 'client = boto3.client(\'cloudformation\')',
        'user_function': 'list_stacks(), detect_stack_drift()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Enable drift detection for CloudFormation stacks'
    }

COMPLIANCE_DATA = load_compliance_metadata('cloudformation_stack_drift_detection_enabled')

def cloudformation_stack_drift_detection_enabled_check(cloudformation_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for cloudformation_stack_drift_detection_enabled.
    """
    findings = []
    
    try:
        # Get all CloudFormation stacks
        paginator = cloudformation_client.get_paginator('list_stacks')
        stacks = []
        
        # Only get stacks that are not deleted
        valid_statuses = [
            'CREATE_COMPLETE', 'CREATE_IN_PROGRESS', 'CREATE_FAILED',
            'UPDATE_COMPLETE', 'UPDATE_IN_PROGRESS', 'UPDATE_COMPLETE_CLEANUP_IN_PROGRESS',
            'UPDATE_FAILED', 'UPDATE_ROLLBACK_COMPLETE', 'UPDATE_ROLLBACK_FAILED',
            'UPDATE_ROLLBACK_IN_PROGRESS', 'ROLLBACK_COMPLETE', 'ROLLBACK_FAILED',
            'ROLLBACK_IN_PROGRESS', 'REVIEW_IN_PROGRESS', 'IMPORT_COMPLETE',
            'IMPORT_IN_PROGRESS', 'IMPORT_ROLLBACK_COMPLETE', 'IMPORT_ROLLBACK_FAILED',
            'IMPORT_ROLLBACK_IN_PROGRESS'
        ]
        
        for page in paginator.paginate():
            page_stacks = page.get('StackSummaries', [])
            # Filter out deleted stacks
            active_stacks = [stack for stack in page_stacks if stack.get('StackStatus') in valid_statuses]
            stacks.extend(active_stacks)
        
        if not stacks:
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'CloudFormation Stack',
                'resource_id': f'no-stacks-{region}',
                'status': 'COMPLIANT',
                'compliance_status': 'PASS',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable drift detection for CloudFormation stacks'),
                'details': {
                    'message': 'No active CloudFormation stacks found in this region',
                    'stack_count': 0
                }
            }
            findings.append(finding)
            return findings
        
        # Check drift detection for each stack
        for stack in stacks:
            stack_name = stack.get('StackName')
            stack_id = stack.get('StackId')
            stack_status = stack.get('StackStatus')
            
            try:
                # Check if stack supports drift detection
                stack_details = cloudformation_client.describe_stacks(StackName=stack_name)
                stack_info = stack_details.get('Stacks', [{}])[0]
                drift_information = stack_info.get('DriftInformation', {})
                
                # Get drift detection status
                stack_drift_status = drift_information.get('StackDriftStatus', 'NOT_CHECKED')
                last_check_timestamp = drift_information.get('LastCheckTimestamp')
                
                # Check if drift detection has been performed
                if stack_drift_status == 'NOT_CHECKED':
                    status = 'NON_COMPLIANT'
                    compliance_status = 'FAIL'
                    message = f'CloudFormation stack {stack_name} has not been checked for drift'
                else:
                    status = 'COMPLIANT'
                    compliance_status = 'PASS'
                    message = f'CloudFormation stack {stack_name} has drift detection enabled'
                
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'CloudFormation Stack',
                    'resource_id': stack_id,
                    'status': status,
                    'compliance_status': compliance_status,
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable drift detection for CloudFormation stacks'),
                    'details': {
                        'stack_name': stack_name,
                        'stack_id': stack_id,
                        'stack_status': stack_status,
                        'drift_status': stack_drift_status,
                        'last_check_timestamp': str(last_check_timestamp) if last_check_timestamp else None,
                        'drift_detection_enabled': stack_drift_status != 'NOT_CHECKED',
                        'message': message
                    }
                }
                findings.append(finding)
                
            except Exception as e:
                logger.error(f"Error checking drift for stack {stack_name}: {e}")
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'CloudFormation Stack',
                    'resource_id': stack_id,
                    'status': 'ERROR',
                    'compliance_status': 'ERROR',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable drift detection for CloudFormation stacks'),
                    'error': str(e),
                    'details': {
                        'stack_name': stack_name,
                        'stack_id': stack_id,
                        'stack_status': stack_status,
                        'message': f'Error checking drift detection for stack {stack_name}'
                    }
                }
                findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in cloudformation_stack_drift_detection_enabled check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'CloudFormation Stack',
            'resource_id': f'error-{region}',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable drift detection for CloudFormation stacks'),
            'error': str(e)
        })
        
    return findings

def cloudformation_stack_drift_detection_enabled(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=cloudformation_stack_drift_detection_enabled_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    args = setup_command_line_interface(COMPLIANCE_DATA)
    results = cloudformation_stack_drift_detection_enabled(
        profile_name=args.profile,
        region_name=args.region
    )
    save_results(results, args.output, args.verbose)
    exit_with_status(results)
#!/usr/bin/env python3
"""
iso27001_2022_aws - dlm_ebs_snapshot_lifecycle_policy_exists

Data loss prevention information system should operate effectively to reduce unauthorized data loss.
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
        'compliance_name': 'iso27001_2022_aws',
        'function_name': 'dlm_ebs_snapshot_lifecycle_policy_exists',
        'id': 'ISO-27001-2022-A.12.3',
        'name': 'Data Loss Prevention',
        'description': 'Data loss prevention information system should operate effectively to reduce unauthorized data loss.',
        'api_function': 'client = boto3.client(\'dlm\')',
        'user_function': 'get_lifecycle_policies()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Configure EBS snapshot lifecycle policies to ensure automated backup and data protection'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('dlm_ebs_snapshot_lifecycle_policy_exists')

def dlm_ebs_snapshot_lifecycle_policy_exists_check(dlm_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for dlm_ebs_snapshot_lifecycle_policy_exists.
    
    Args:
        dlm_client: Boto3 DLM client (auto-created by framework)
        region (str): AWS region (auto-managed by framework)
        profile (str): AWS profile name (auto-managed by framework)
        logger: Logger instance (auto-configured by framework)
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    try:
        # Get all lifecycle policies in the region
        response = dlm_client.get_lifecycle_policies()
        policies = response.get('Policies', [])
        
        # Count active EBS snapshot policies
        active_ebs_policies = []
        for policy in policies:
            policy_id = policy.get('PolicyId', 'unknown')
            state = policy.get('State', 'unknown')
            policy_type = policy.get('PolicyType', 'unknown')
            
            # Check if it's an active EBS snapshot policy
            if state == 'ENABLED' and policy_type == 'EBS_SNAPSHOT_MANAGEMENT':
                active_ebs_policies.append({
                    'policy_id': policy_id,
                    'state': state,
                    'policy_type': policy_type,
                    'description': policy.get('Description', 'No description')
                })
        
        # Determine compliance status
        if active_ebs_policies:
            # EBS snapshot lifecycle policies exist and are active
            status = 'COMPLIANT'
            compliance_status = 'PASS'
            recommendation = f'Found {len(active_ebs_policies)} active EBS snapshot lifecycle policies'
        else:
            # No active EBS snapshot lifecycle policies found
            status = 'NON_COMPLIANT'
            compliance_status = 'FAIL'
            recommendation = COMPLIANCE_DATA.get('recommendation', 'Configure EBS snapshot lifecycle policies to ensure automated backup and data protection')
        
        finding = {
            'region': region,
            'profile': profile,
            'resource_type': 'DLM',
            'resource_id': f'dlm-policies-{region}',
            'status': status,
            'compliance_status': compliance_status,
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': recommendation,
            'details': {
                'total_policies': len(policies),
                'active_ebs_policies_count': len(active_ebs_policies),
                'active_ebs_policies': active_ebs_policies,
                'all_policies': policies
            }
        }
        
        findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in dlm_ebs_snapshot_lifecycle_policy_exists check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'DLM',
            'resource_id': f'error-check-{region}',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Configure EBS snapshot lifecycle policies to ensure automated backup and data protection'),
            'error': str(e)
        })
        
    return findings

def dlm_ebs_snapshot_lifecycle_policy_exists(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=dlm_ebs_snapshot_lifecycle_policy_exists_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = dlm_ebs_snapshot_lifecycle_policy_exists(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

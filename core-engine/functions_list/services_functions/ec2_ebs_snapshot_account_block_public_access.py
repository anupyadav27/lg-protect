#!/usr/bin/env python3
"""
iso27001_2022_aws - ec2_ebs_snapshot_account_block_public_access

Check that Amazon EBS snapshots are not publicly restorable by everyone
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
                    'recommendation': entry.get('Recommendation', 'Enable account-level public access block for EBS snapshots')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'iso27001_2022_aws',
        'function_name': 'ec2_ebs_snapshot_account_block_public_access',
        'id': 'ISO-27001-2022-A.8.24',
        'name': 'Information Security in Project Management',
        'description': 'Check that Amazon EBS snapshots are not publicly restorable by everyone',
        'api_function': 'client = boto3.client(\'ec2\')',
        'user_function': 'get_ebs_encryption_by_default(), get_ebs_default_kms_key_id()',
        'risk_level': 'HIGH',
        'recommendation': 'Enable account-level public access block for EBS snapshots to prevent unauthorized access'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('ec2_ebs_snapshot_account_block_public_access')

def ec2_ebs_snapshot_account_block_public_access_check(ec2_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for ec2_ebs_snapshot_account_block_public_access.
    
    Args:
        ec2_client: Boto3 EC2 client (auto-created by framework)
        region (str): AWS region (auto-managed by framework)
        profile (str): AWS profile name (auto-managed by framework)
        logger: Logger instance (auto-configured by framework)
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    try:
        # Check account-level snapshot block public access configuration
        try:
            response = ec2_client.get_snapshot_block_public_access_state()
            block_state = response.get('State', 'unblocked')
            
            # Determine compliance status
            if block_state == 'block-all-sharing':
                status = 'COMPLIANT'
                compliance_status = 'PASS'
                risk_level = 'LOW'
                recommendation = 'Account-level public access blocking for EBS snapshots is properly configured'
            elif block_state == 'block-new-sharing':
                status = 'NON_COMPLIANT'
                compliance_status = 'FAIL'
                risk_level = COMPLIANCE_DATA.get('risk_level', 'MEDIUM')
                recommendation = 'Enable full blocking (block-all-sharing) for enhanced security'
            else:  # unblocked
                status = 'NON_COMPLIANT'
                compliance_status = 'FAIL'
                risk_level = COMPLIANCE_DATA.get('risk_level', 'HIGH')
                recommendation = COMPLIANCE_DATA.get('recommendation', 'Enable account-level public access block for EBS snapshots')
            
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'EC2 Account Settings',
                'resource_id': f'snapshot-block-public-access-{region}',
                'status': status,
                'compliance_status': compliance_status,
                'risk_level': risk_level,
                'recommendation': recommendation,
                'details': {
                    'block_public_access_state': block_state,
                    'account_setting': 'Snapshot Block Public Access',
                    'region': region,
                    'is_compliant': status == 'COMPLIANT',
                    'security_note': 'Block public access prevents EBS snapshots from being shared publicly'
                }
            }
            
            findings.append(finding)
            
        except Exception as api_error:
            # If API call fails, it might mean the feature is not available in the region
            logger.warning(f"Could not check snapshot block public access state: {api_error}")
            
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'EC2 Account Settings',
                'resource_id': f'snapshot-block-public-access-{region}',
                'status': 'ERROR',
                'compliance_status': 'ERROR',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                'recommendation': 'Unable to check snapshot block public access state - feature may not be available in this region',
                'details': {
                    'error': str(api_error),
                    'account_setting': 'Snapshot Block Public Access',
                    'region': region,
                    'note': 'API call failed - check if feature is supported in this region'
                }
            }
            
            findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in ec2_ebs_snapshot_account_block_public_access check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'EC2 Account Settings',
            'resource_id': f'error-check-{region}',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable account-level public access block for EBS snapshots'),
            'error': str(e)
        })
        
    return findings

def ec2_ebs_snapshot_account_block_public_access(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=ec2_ebs_snapshot_account_block_public_access_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = ec2_ebs_snapshot_account_block_public_access(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

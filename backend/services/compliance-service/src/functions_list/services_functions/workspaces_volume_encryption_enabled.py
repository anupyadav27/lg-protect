#!/usr/bin/env python3
"""
iso27001_2022_aws - workspaces_volume_encryption_enabled

Rules for the effective use of cryptography, including cryptographic key management, should be defined and implemented.
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
        'function_name': 'workspaces_volume_encryption_enabled',
        'id': 'WS-001',
        'name': 'WorkSpaces Volume Encryption',
        'description': 'Rules for the effective use of cryptography, including cryptographic key management, should be defined and implemented.',
        'api_function': 'client=boto3.client("workspaces")',
        'user_function': 'describe_workspaces()',
        'risk_level': 'HIGH',
        'recommendation': 'Enable encryption for all WorkSpaces volumes to ensure data protection'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('workspaces_volume_encryption_enabled')

def workspaces_volume_encryption_enabled_check(workspaces_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for workspaces_volume_encryption_enabled.
    
    Args:
        workspaces_client: Boto3 WorkSpaces client (auto-created by framework)
        region (str): AWS region (auto-managed by framework)
        profile (str): AWS profile name (auto-managed by framework)
        logger: Logger instance (auto-configured by framework)
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    try:
        # Describe all WorkSpaces
        paginator = workspaces_client.get_paginator('describe_workspaces')
        
        for page in paginator.paginate():
            workspaces = page.get('Workspaces', [])
            
            if not workspaces:
                logger.info(f"No WorkSpaces found in region {region}")
                continue
            
            for workspace in workspaces:
                workspace_id = workspace.get('WorkspaceId', 'Unknown')
                username = workspace.get('UserName', 'Unknown')
                directory_id = workspace.get('DirectoryId', 'Unknown')
                state = workspace.get('State', 'Unknown')
                bundle_id = workspace.get('BundleId', 'Unknown')
                
                # Get workspace properties to check encryption settings
                workspace_properties = workspace.get('WorkspaceProperties', {})
                user_volume_encryption_enabled = workspace_properties.get('UserVolumeEncryptionEnabled', False)
                root_volume_encryption_enabled = workspace_properties.get('RootVolumeEncryptionEnabled', False)
                
                # Check if both volumes are encrypted
                is_compliant = user_volume_encryption_enabled and root_volume_encryption_enabled
                
                if is_compliant:
                    # Both volumes encrypted - COMPLIANT
                    finding = {
                        'region': region,
                        'profile': profile,
                        'resource_type': 'WorkSpace',
                        'resource_id': f"{workspace_id} ({username})",
                        'status': 'COMPLIANT',
                        'compliance_status': 'PASS',
                        'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                        'recommendation': COMPLIANCE_DATA.get('recommendation', 'Maintain encryption settings'),
                        'details': {
                            'workspace_id': workspace_id,
                            'username': username,
                            'directory_id': directory_id,
                            'state': state,
                            'bundle_id': bundle_id,
                            'user_volume_encrypted': user_volume_encryption_enabled,
                            'root_volume_encrypted': root_volume_encryption_enabled,
                            'computer_name': workspace.get('ComputerName', 'Unknown'),
                            'ip_address': workspace.get('IpAddress', 'Unknown')
                        }
                    }
                else:
                    # One or both volumes not encrypted - NON_COMPLIANT
                    encryption_issues = []
                    if not user_volume_encryption_enabled:
                        encryption_issues.append('User volume not encrypted')
                    if not root_volume_encryption_enabled:
                        encryption_issues.append('Root volume not encrypted')
                    
                    finding = {
                        'region': region,
                        'profile': profile,
                        'resource_type': 'WorkSpace',
                        'resource_id': f"{workspace_id} ({username})",
                        'status': 'NON_COMPLIANT',
                        'compliance_status': 'FAIL',
                        'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                        'recommendation': 'Enable encryption for all WorkSpace volumes',
                        'details': {
                            'workspace_id': workspace_id,
                            'username': username,
                            'directory_id': directory_id,
                            'state': state,
                            'bundle_id': bundle_id,
                            'user_volume_encrypted': user_volume_encryption_enabled,
                            'root_volume_encrypted': root_volume_encryption_enabled,
                            'computer_name': workspace.get('ComputerName', 'Unknown'),
                            'ip_address': workspace.get('IpAddress', 'Unknown'),
                            'issues': encryption_issues
                        }
                    }
                
                findings.append(finding)
        
        if not findings:
            logger.info(f"No WorkSpaces found in region {region}")
        
    except Exception as e:
        logger.error(f"Error in workspaces_volume_encryption_enabled check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'WorkSpace',
            'status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Review WorkSpaces configuration'),
            'error': str(e)
        })
        
    return findings

def workspaces_volume_encryption_enabled(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=workspaces_volume_encryption_enabled_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = workspaces_volume_encryption_enabled(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

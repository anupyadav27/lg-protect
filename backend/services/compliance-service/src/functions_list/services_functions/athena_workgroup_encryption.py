#!/usr/bin/env python3
"""
iso27001_2022_aws - athena_workgroup_encryption

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
        'function_name': 'athena_workgroup_encryption',
        'id': 'A.10.1',
        'name': 'Cryptographic Controls',
        'description': 'Rules for the effective use of cryptography, including cryptographic key management, should be defined and implemented.',
        'api_function': 'client = boto3.client("athena")',
        'user_function': 'list_work_groups(), get_work_group(WorkGroup="string")',
        'risk_level': 'MEDIUM',
        'recommendation': 'Enable encryption at rest for all Athena workgroups'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('athena_workgroup_encryption')

def athena_workgroup_encryption_check(athena_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for athena_workgroup_encryption.
    
    Args:
        athena_client: Boto3 athena client (auto-created by framework)
        region (str): AWS region (auto-managed by framework)
        profile (str): AWS profile name (auto-managed by framework)
        logger: Logger instance (auto-configured by framework)
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    try:
        # Get all workgroups
        paginator = athena_client.get_paginator('list_work_groups')
        workgroups = []
        
        for page in paginator.paginate():
            workgroups.extend(page.get('WorkGroups', []))
        
        if not workgroups:
            # No workgroups found
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'Athena Workgroup',
                'resource_id': f'no-workgroups-{region}',
                'status': 'COMPLIANT',
                'compliance_status': 'PASS',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                'recommendation': 'No Athena workgroups found',
                'details': {
                    'workgroups_count': 0,
                    'encrypted_workgroups': 0,
                    'non_encrypted_workgroups': 0
                }
            }
            findings.append(finding)
            return findings
        
        encrypted_workgroups = []
        non_encrypted_workgroups = []
        
        # Check each workgroup for encryption
        for workgroup_summary in workgroups:
            workgroup_name = workgroup_summary.get('Name', '')
            
            try:
                # Get detailed workgroup configuration
                response = athena_client.get_work_group(WorkGroup=workgroup_name)
                workgroup_config = response.get('WorkGroup', {})
                configuration = workgroup_config.get('Configuration', {})
                result_config = configuration.get('ResultConfiguration', {})
                
                # Check for encryption configuration
                encryption_config = result_config.get('EncryptionConfiguration', {})
                encryption_option = encryption_config.get('EncryptionOption', '')
                kms_key = encryption_config.get('KmsKey', '')
                
                workgroup_details = {
                    'workgroup_name': workgroup_name,
                    'state': workgroup_config.get('State', 'UNKNOWN'),
                    'creation_time': workgroup_config.get('CreationTime'),
                    'encryption_option': encryption_option,
                    'kms_key': kms_key,
                    'output_location': result_config.get('OutputLocation', '')
                }
                
                if encryption_option in ['SSE_S3', 'SSE_KMS']:
                    encrypted_workgroups.append(workgroup_details)
                    
                    finding = {
                        'region': region,
                        'profile': profile,
                        'resource_type': 'Athena Workgroup',
                        'resource_id': workgroup_name,
                        'status': 'COMPLIANT',
                        'compliance_status': 'PASS',
                        'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                        'recommendation': 'Workgroup encryption is properly configured',
                        'details': workgroup_details
                    }
                    findings.append(finding)
                else:
                    non_encrypted_workgroups.append(workgroup_details)
                    
                    finding = {
                        'region': region,
                        'profile': profile,
                        'resource_type': 'Athena Workgroup',
                        'resource_id': workgroup_name,
                        'status': 'NON_COMPLIANT',
                        'compliance_status': 'FAIL',
                        'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                        'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable encryption at rest for Athena workgroup'),
                        'details': workgroup_details
                    }
                    findings.append(finding)
                    
            except Exception as e:
                logger.warning(f"Error checking workgroup {workgroup_name}: {e}")
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'Athena Workgroup',
                    'resource_id': workgroup_name,
                    'status': 'ERROR',
                    'compliance_status': 'ERROR',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                    'recommendation': 'Unable to determine encryption configuration',
                    'error': str(e),
                    'details': {
                        'workgroup_name': workgroup_name,
                        'error_details': str(e)
                    }
                }
                findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in athena_workgroup_encryption check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'Athena Workgroup',
            'status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Review and remediate as needed'),
            'error': str(e)
        })
        
    return findings

def athena_workgroup_encryption(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=athena_workgroup_encryption_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = athena_workgroup_encryption(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

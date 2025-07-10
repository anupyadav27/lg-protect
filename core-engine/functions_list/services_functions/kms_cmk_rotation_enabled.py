#!/usr/bin/env python3
"""
iso27001_2022_aws - kms_cmk_rotation_enabled

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
                    'risk_level': entry.get('Risk Level', 'HIGH'),
                    'recommendation': entry.get('Recommendation', 'Enable automatic rotation for customer-managed KMS keys')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'iso27001_2022_aws',
        'function_name': 'kms_cmk_rotation_enabled',
        'id': 'A.10.1.2',
        'name': 'Key Management',
        'description': 'Rules for the effective use of cryptography, including cryptographic key management, should be defined and implemented.',
        'api_function': 'client = boto3.client("kms")',
        'user_function': 'list_keys(), get_key_rotation_status()',
        'risk_level': 'HIGH',
        'recommendation': 'Enable automatic rotation for customer-managed KMS keys'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('kms_cmk_rotation_enabled')

def kms_cmk_rotation_enabled_check(kms_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for kms_cmk_rotation_enabled.
    
    Args:
        kms_client: Boto3 KMS client (auto-created by framework)
        region (str): AWS region (auto-managed by framework)
        profile (str): AWS profile name (auto-managed by framework)
        logger: Logger instance (auto-configured by framework)
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    try:
        logger.info("Checking KMS customer-managed keys for rotation status...")
        
        # Get all KMS keys
        response = kms_client.list_keys()
        keys = response.get('Keys', [])
        
        if not keys:
            logger.info("No KMS keys found in this region")
            return findings
        
        for key in keys:
            key_id = key.get('KeyId', 'Unknown')
            
            try:
                # Get detailed key information
                key_details = kms_client.describe_key(KeyId=key_id)
                key_metadata = key_details.get('KeyMetadata', {})
                
                key_manager = key_metadata.get('KeyManager', 'UNKNOWN')
                key_usage = key_metadata.get('KeyUsage', 'UNKNOWN')
                key_state = key_metadata.get('KeyState', 'UNKNOWN')
                key_spec = key_metadata.get('KeySpec', 'UNKNOWN')
                
                # Only check customer-managed keys
                if key_manager != 'CUSTOMER':
                    continue
                
                # Only check symmetric encryption keys as they support rotation
                if key_usage != 'ENCRYPT_DECRYPT' or key_spec != 'SYMMETRIC_DEFAULT':
                    finding = {
                        'region': region,
                        'profile': profile,
                        'resource_type': 'KMS Key',
                        'resource_id': key_id,
                        'status': 'COMPLIANT',
                        'compliance_status': 'PASS',
                        'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                        'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable automatic rotation for customer-managed KMS keys'),
                        'details': {
                            'key_id': key_id,
                            'key_arn': key_metadata.get('Arn', 'Unknown'),
                            'key_manager': key_manager,
                            'key_usage': key_usage,
                            'key_spec': key_spec,
                            'key_state': key_state,
                            'rotation_applicable': False,
                            'rotation_enabled': 'N/A',
                            'created_date': str(key_metadata.get('CreationDate', 'Unknown')),
                            'description': key_metadata.get('Description', 'No description'),
                            'message': f"Key rotation not applicable for {key_usage} keys with spec {key_spec}"
                        }
                    }
                    findings.append(finding)
                    continue
                
                # Check rotation status for applicable keys
                try:
                    rotation_response = kms_client.get_key_rotation_status(KeyId=key_id)
                    rotation_enabled = rotation_response.get('KeyRotationEnabled', False)
                    
                    # Determine compliance status
                    if rotation_enabled:
                        status = 'COMPLIANT'
                        compliance_status = 'PASS'
                        message = "KMS key has automatic rotation enabled"
                    else:
                        status = 'NON_COMPLIANT'
                        compliance_status = 'FAIL'
                        message = "KMS key does not have automatic rotation enabled"
                    
                    finding = {
                        'region': region,
                        'profile': profile,
                        'resource_type': 'KMS Key',
                        'resource_id': key_id,
                        'status': status,
                        'compliance_status': compliance_status,
                        'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                        'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable automatic rotation for customer-managed KMS keys'),
                        'details': {
                            'key_id': key_id,
                            'key_arn': key_metadata.get('Arn', 'Unknown'),
                            'key_manager': key_manager,
                            'key_usage': key_usage,
                            'key_spec': key_spec,
                            'key_state': key_state,
                            'rotation_applicable': True,
                            'rotation_enabled': rotation_enabled,
                            'created_date': str(key_metadata.get('CreationDate', 'Unknown')),
                            'description': key_metadata.get('Description', 'No description'),
                            'message': message
                        }
                    }
                    
                except Exception as rotation_error:
                    logger.warning(f"Could not check rotation status for key {key_id}: {rotation_error}")
                    finding = {
                        'region': region,
                        'profile': profile,
                        'resource_type': 'KMS Key',
                        'resource_id': key_id,
                        'status': 'ERROR',
                        'compliance_status': 'ERROR',
                        'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                        'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable automatic rotation for customer-managed KMS keys'),
                        'error': str(rotation_error),
                        'details': {
                            'key_id': key_id,
                            'key_arn': key_metadata.get('Arn', 'Unknown'),
                            'key_manager': key_manager,
                            'key_usage': key_usage,
                            'key_spec': key_spec,
                            'key_state': key_state,
                            'rotation_applicable': True,
                            'rotation_enabled': 'ERROR',
                            'error_message': str(rotation_error),
                            'message': f"Could not verify rotation status for key {key_id}"
                        }
                    }
                
                findings.append(finding)
                
            except Exception as e:
                logger.error(f"Error describing key {key_id}: {e}")
                findings.append({
                    'region': region,
                    'profile': profile,
                    'resource_type': 'KMS Key',
                    'resource_id': key_id,
                    'status': 'ERROR',
                    'compliance_status': 'ERROR',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable automatic rotation for customer-managed KMS keys'),
                    'error': str(e),
                    'details': {
                        'key_id': key_id,
                        'error_message': str(e)
                    }
                })
            
    except Exception as e:
        logger.error(f"Error in kms_cmk_rotation_enabled check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'KMS Key',
            'resource_id': 'Unknown',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable automatic rotation for customer-managed KMS keys'),
            'error': str(e),
            'details': {
                'error_message': str(e),
                'check_type': 'kms_cmk_rotation_enabled'
            }
        })
        
    return findings

def kms_cmk_rotation_enabled(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=kms_cmk_rotation_enabled_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = kms_cmk_rotation_enabled(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

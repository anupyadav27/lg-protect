#!/usr/bin/env python3
"""
iso27001_2022_aws - kms_cmk_are_used

Rules for the effective use of cryptography, including cryptographic key management, should be defined and implemented.
"""

import sys
import os
import json
from typing import Dict, List, Any
from datetime import datetime, timedelta

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
                    'recommendation': entry.get('Recommendation', 'Remove unused KMS keys to reduce security exposure')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'iso27001_2022_aws',
        'function_name': 'kms_cmk_are_used',
        'id': 'A.10.1.2',
        'name': 'Key Management',
        'description': 'Rules for the effective use of cryptography, including cryptographic key management, should be defined and implemented.',
        'api_function': 'client = boto3.client("kms")',
        'user_function': 'list_keys(), describe_key()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Remove unused KMS keys to reduce security exposure'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('kms_cmk_are_used')

def kms_cmk_are_used_check(kms_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for kms_cmk_are_used.
    
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
        logger.info("Checking KMS customer-managed keys for usage...")
        
        # Get all KMS keys
        response = kms_client.list_keys()
        keys = response.get('Keys', [])
        
        if not keys:
            logger.info("No KMS keys found in this region")
            return findings
        
        # Define threshold for considering a key unused (e.g., 90 days)
        unused_threshold_days = 90
        threshold_date = datetime.now() - timedelta(days=unused_threshold_days)
        
        for key in keys:
            key_id = key.get('KeyId', 'Unknown')
            
            try:
                # Get detailed key information
                key_details = kms_client.describe_key(KeyId=key_id)
                key_metadata = key_details.get('KeyMetadata', {})
                
                key_manager = key_metadata.get('KeyManager', 'UNKNOWN')
                key_usage = key_metadata.get('KeyUsage', 'UNKNOWN')
                key_state = key_metadata.get('KeyState', 'UNKNOWN')
                creation_date = key_metadata.get('CreationDate', None)
                
                # Only check customer-managed keys
                if key_manager != 'CUSTOMER':
                    continue
                
                # Skip keys that are not enabled
                if key_state != 'Enabled':
                    continue
                
                # Check key usage through CloudTrail-like analysis
                # Note: This is a simplified check - in reality, you'd want to check CloudTrail logs
                # for actual KMS API usage (Encrypt, Decrypt, GenerateDataKey, etc.)
                
                is_key_used = True  # Default assumption
                last_used_info = "Usage information not available"
                
                # For demonstration, we'll consider a key "unused" if it's very old and has no aliases
                try:
                    aliases_response = kms_client.list_aliases(KeyId=key_id)
                    aliases = aliases_response.get('Aliases', [])
                    
                    # If key has no aliases and is older than threshold, consider it potentially unused
                    if not aliases and creation_date and creation_date < threshold_date:
                        is_key_used = False
                        last_used_info = f"Key created over {unused_threshold_days} days ago with no aliases"
                    elif aliases:
                        last_used_info = f"Key has {len(aliases)} alias(es): {[alias.get('AliasName', 'Unknown') for alias in aliases]}"
                    else:
                        last_used_info = "Key created recently or usage cannot be determined"
                        
                except Exception as alias_error:
                    logger.warning(f"Could not check aliases for key {key_id}: {alias_error}")
                    last_used_info = "Could not determine alias information"
                
                # Determine compliance status
                if is_key_used:
                    status = 'COMPLIANT'
                    compliance_status = 'PASS'
                    message = "KMS key appears to be in use"
                else:
                    status = 'NON_COMPLIANT'
                    compliance_status = 'FAIL'
                    message = "KMS key appears to be unused"
                
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'KMS Key',
                    'resource_id': key_id,
                    'status': status,
                    'compliance_status': compliance_status,
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Remove unused KMS keys to reduce security exposure'),
                    'details': {
                        'key_id': key_id,
                        'key_arn': key_metadata.get('Arn', 'Unknown'),
                        'key_manager': key_manager,
                        'key_usage': key_usage,
                        'key_state': key_state,
                        'is_key_used': is_key_used,
                        'last_used_info': last_used_info,
                        'created_date': str(creation_date) if creation_date else 'Unknown',
                        'description': key_metadata.get('Description', 'No description'),
                        'message': message
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
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Remove unused KMS keys to reduce security exposure'),
                    'error': str(e),
                    'details': {
                        'key_id': key_id,
                        'error_message': str(e)
                    }
                })
            
    except Exception as e:
        logger.error(f"Error in kms_cmk_are_used check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'KMS Key',
            'resource_id': 'Unknown',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Remove unused KMS keys to reduce security exposure'),
            'error': str(e),
            'details': {
                'error_message': str(e),
                'check_type': 'kms_cmk_are_used'
            }
        })
        
    return findings

def kms_cmk_are_used(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=kms_cmk_are_used_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = kms_cmk_are_used(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

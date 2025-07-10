#!/usr/bin/env python3
"""
cisa_aws - ec2_ebs_default_encryption

Learn how your data is protected.
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
                    'recommendation': entry.get('Recommendation', 'Enable EBS default encryption')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'cisa_aws',
        'function_name': 'ec2_ebs_default_encryption',
        'id': 'your-data-1',
        'name': 'Your Data-1',
        'description': 'Learn how your data is protected.',
        'api_function': 'client = boto3.client(\'ec2\')',
        'user_function': 'describe_volumes_modifications()',
        'risk_level': 'HIGH',
        'recommendation': 'Enable default EBS encryption to ensure all new volumes are encrypted'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('ec2_ebs_default_encryption')

def ec2_ebs_default_encryption_check(ec2_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for ec2_ebs_default_encryption.
    
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
        # Check if EBS encryption by default is enabled
        response = ec2_client.get_ebs_encryption_by_default()
        encryption_by_default = response.get('EbsEncryptionByDefault', False)
        
        # Get the default KMS key if encryption is enabled
        default_kms_key = None
        if encryption_by_default:
            try:
                kms_response = ec2_client.get_ebs_default_kms_key_id()
                default_kms_key = kms_response.get('KmsKeyId', 'aws/ebs')
            except Exception as kms_error:
                logger.warning(f"Could not get default KMS key: {kms_error}")
                default_kms_key = 'unknown'
        
        # Determine compliance status
        if encryption_by_default:
            status = 'COMPLIANT'
            compliance_status = 'PASS'
            risk_level = 'LOW'
            recommendation = 'EBS default encryption is properly enabled'
        else:
            status = 'NON_COMPLIANT'
            compliance_status = 'FAIL'
            risk_level = COMPLIANCE_DATA.get('risk_level', 'HIGH')
            recommendation = COMPLIANCE_DATA.get('recommendation', 'Enable default EBS encryption')
        
        finding = {
            'region': region,
            'profile': profile,
            'resource_type': 'EC2 Account Settings',
            'resource_id': f'ebs-default-encryption-{region}',
            'status': status,
            'compliance_status': compliance_status,
            'risk_level': risk_level,
            'recommendation': recommendation,
            'details': {
                'ebs_encryption_by_default': encryption_by_default,
                'default_kms_key_id': default_kms_key,
                'region': region,
                'account_setting': 'EBS Default Encryption',
                'is_compliant': encryption_by_default,
                'security_note': 'Default encryption ensures all new EBS volumes are automatically encrypted'
            }
        }
        
        findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in ec2_ebs_default_encryption check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'EC2 Account Settings',
            'resource_id': f'error-check-{region}',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable default EBS encryption'),
            'error': str(e)
        })
        
    return findings

def ec2_ebs_default_encryption(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=ec2_ebs_default_encryption_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = ec2_ebs_default_encryption(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

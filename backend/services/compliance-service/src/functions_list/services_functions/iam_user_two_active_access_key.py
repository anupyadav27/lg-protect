#!/usr/bin/env python3
"""
cis_1.4_aws - iam_user_two_active_access_key

Ensure there is only one active access key available for any single IAM user
"""

import sys
import os
import json
import csv
import base64
from typing import Dict, List, Any
from datetime import datetime

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
                    'recommendation': entry.get('Recommendation', 'Ensure only one active access key per IAM user')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'cis_1.4_aws',
        'function_name': 'iam_user_two_active_access_key',
        'id': '1.13',
        'name': 'Ensure there is only one active access key available for any single IAM user',
        'description': 'Ensure there is only one active access key available for any single IAM user',
        'api_function': 'client = boto3.client(\'iam\')',
        'user_function': 'get_credential_report()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Ensure only one active access key per IAM user'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('iam_user_two_active_access_key')

def iam_user_two_active_access_key_check(iam_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for iam_user_two_active_access_key.
    
    Args:
        iam_client: Boto3 IAM client (auto-created by framework)
        region (str): AWS region (auto-managed by framework)
        profile (str): AWS profile name (auto-managed by framework)
        logger: Logger instance (auto-configured by framework)
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    try:
        # Generate and get credential report
        logger.info("Generating credential report...")
        
        # Generate credential report (may take some time)
        try:
            iam_client.generate_credential_report()
        except Exception as e:
            logger.warning(f"Could not generate credential report: {e}")
        
        # Get the credential report
        response = iam_client.get_credential_report()
        
        # Decode the CSV content
        csv_content = base64.b64decode(response['Content']).decode('utf-8')
        
        # Parse CSV data
        csv_reader = csv.DictReader(csv_content.splitlines())
        
        for row in csv_reader:
            username = row.get('user', 'Unknown')
            
            # Skip root user
            if username == '<root_account>':
                continue
                
            # Check access key status
            access_key_1_active = row.get('access_key_1_active', 'false').lower() == 'true'
            access_key_2_active = row.get('access_key_2_active', 'false').lower() == 'true'
            
            # Count active access keys
            active_key_count = sum([access_key_1_active, access_key_2_active])
            
            # Determine compliance status
            if active_key_count <= 1:
                status = 'COMPLIANT'
                compliance_status = 'PASS'
                details_msg = f"User has {active_key_count} active access key(s)"
            else:
                status = 'NON_COMPLIANT'
                compliance_status = 'FAIL'
                details_msg = f"User has {active_key_count} active access keys (should be 1 or fewer)"
            
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'IAM User',
                'resource_id': username,
                'status': status,
                'compliance_status': compliance_status,
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                'recommendation': COMPLIANCE_DATA.get('recommendation', 'Ensure only one active access key per IAM user'),
                'details': {
                    'username': username,
                    'active_access_key_count': active_key_count,
                    'access_key_1_active': access_key_1_active,
                    'access_key_2_active': access_key_2_active,
                    'access_key_1_last_used': row.get('access_key_1_last_used_date', 'N/A'),
                    'access_key_2_last_used': row.get('access_key_2_last_used_date', 'N/A'),
                    'message': details_msg
                }
            }
            
            findings.append(finding)
            
    except Exception as e:
        logger.error(f"Error in iam_user_two_active_access_key check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'IAM User',
            'resource_id': 'Unknown',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Ensure only one active access key per IAM user'),
            'error': str(e),
            'details': {
                'error_message': str(e),
                'check_type': 'iam_user_two_active_access_key'
            }
        })
        
    return findings

def iam_user_two_active_access_key(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=iam_user_two_active_access_key_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = iam_user_two_active_access_key(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

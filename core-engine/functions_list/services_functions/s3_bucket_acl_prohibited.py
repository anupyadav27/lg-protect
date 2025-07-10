#!/usr/bin/env python3
"""
s3_bucket_acl_prohibited - Checks if S3 bucket ACLs are prohibited

This compliance check verifies that S3 buckets have ACLs disabled to enforce bucket ownership controls.
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
        'compliance_name': 'aws_foundational_security_standard',
        'function_name': 's3_bucket_acl_prohibited',
        'id': 'S3.8',
        'name': 'S3 bucket ACL should be prohibited',
        'description': 'Checks if S3 bucket ACLs are prohibited',
        'api_function': 'client = boto3.client("s3")',
        'user_function': 'get_bucket_ownership_controls()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Configure S3 bucket ownership controls to disable ACLs'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('s3_bucket_acl_prohibited')

def s3_bucket_acl_prohibited_check(s3_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for s3_bucket_acl_prohibited.
    
    Args:
        s3_client: Boto3 S3 client (auto-created by framework)
        region (str): AWS region (auto-managed by framework)
        profile (str): AWS profile name (auto-managed by framework)
        logger: Logger instance (auto-configured by framework)
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    try:
        # List all S3 buckets
        response = s3_client.list_buckets()
        buckets = response.get('Buckets', [])
        
        for bucket in buckets:
            bucket_name = bucket['Name']
            
            try:
                # Check bucket ownership controls
                ownership_response = s3_client.get_bucket_ownership_controls(Bucket=bucket_name)
                ownership_controls = ownership_response.get('OwnershipControls', {})
                rules = ownership_controls.get('Rules', [])
                
                # Check if ACLs are disabled
                acls_disabled = False
                for rule in rules:
                    if rule.get('ObjectOwnership') == 'BucketOwnerEnforced':
                        acls_disabled = True
                        break
                
                status = 'COMPLIANT' if acls_disabled else 'NON_COMPLIANT'
                compliance_status = 'PASS' if acls_disabled else 'FAIL'
                
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'S3_BUCKET',
                    'resource_id': bucket_name,
                    'status': status,
                    'compliance_status': compliance_status,
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Configure S3 bucket ownership controls to disable ACLs'),
                    'details': {
                        'bucket_name': bucket_name,
                        'ownership_controls': ownership_controls,
                        'acls_disabled': acls_disabled
                    }
                }
                
            except s3_client.exceptions.NoSuchBucketPolicy:
                # No ownership controls configured - non-compliant
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'S3_BUCKET',
                    'resource_id': bucket_name,
                    'status': 'NON_COMPLIANT',
                    'compliance_status': 'FAIL',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Configure S3 bucket ownership controls to disable ACLs'),
                    'details': {
                        'bucket_name': bucket_name,
                        'ownership_controls': None,
                        'acls_disabled': False,
                        'reason': 'No ownership controls configured'
                    }
                }
            except Exception as bucket_error:
                logger.warning(f"Could not check ownership controls for bucket {bucket_name}: {bucket_error}")
                continue
                
            findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in s3_bucket_acl_prohibited check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'S3_BUCKET',
            'status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Configure S3 bucket ownership controls to disable ACLs'),
            'error': str(e)
        })
        
    return findings

def s3_bucket_acl_prohibited(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=s3_bucket_acl_prohibited_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = s3_bucket_acl_prohibited(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

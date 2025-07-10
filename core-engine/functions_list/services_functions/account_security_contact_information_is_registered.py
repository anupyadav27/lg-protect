#!/usr/bin/env python3
"""
cis_4.0_aws - account_security_contact_information_is_registered

Ensure security contact information is registered
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
        'compliance_name': 'cis_4.0_aws',
        'function_name': 'account_security_contact_information_is_registered',
        'id': 'Account.1',
        'name': 'Security contact information should be provided for an AWS account',
        'description': 'Ensure security contact information is registered',
        'api_function': 'client = boto3.client(\'support\')',
        'user_function': 'describe_cases()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Register security contact information in AWS account'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('account_security_contact_information_is_registered')

def account_security_contact_information_is_registered_check(account_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for account_security_contact_information_is_registered.
    
    Args:
        account_client: Boto3 account service client (auto-created by framework)
        region (str): AWS region (auto-managed by framework)
        profile (str): AWS profile name (auto-managed by framework)
        logger: Logger instance (auto-configured by framework)
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    try:
        # Try to get security contact information using account service
        import boto3
        from botocore.exceptions import ClientError
        
        session = boto3.Session(profile_name=profile if profile != 'default' else None)
        
        # Try different approaches to check security contact information
        security_contact_configured = False
        contact_details = {}
        
        try:
            # Method 1: Try using account service
            account_client = session.client('account', region_name=region)
            contact_response = account_client.get_contact_information()
            
            contact_info = contact_response.get('ContactInformation', {})
            if (contact_info.get('FullName') and 
                contact_info.get('PhoneNumber') and 
                contact_info.get('EmailAddress')):
                security_contact_configured = True
                contact_details = {
                    'full_name': contact_info.get('FullName'),
                    'phone_number': '***-***-' + contact_info.get('PhoneNumber', '')[-4:],  # Mask phone
                    'email_domain': contact_info.get('EmailAddress', '').split('@')[-1] if '@' in contact_info.get('EmailAddress', '') else None
                }
        except ClientError as e:
            if e.response['Error']['Code'] in ['AccessDenied', 'UnauthorizedOperation']:
                logger.warning(f"Access denied when checking account contact information: {e}")
            else:
                logger.warning(f"Error checking account contact information: {e}")
        except Exception as e:
            logger.warning(f"Error with account service: {e}")
        
        # Method 2: Try using support service (alternative approach)
        if not security_contact_configured:
            try:
                support_client = session.client('support', region_name='us-east-1')  # Support is only in us-east-1
                
                # Check if we can access support (indicates some level of contact info)
                cases_response = support_client.describe_cases(maxResults=1)
                # If we can access support without error, basic contact info likely exists
                # But this doesn't guarantee security contact specifically
                
            except ClientError as e:
                if e.response['Error']['Code'] == 'SubscriptionRequiredError':
                    logger.info("AWS Support subscription not available")
                elif e.response['Error']['Code'] in ['AccessDenied', 'UnauthorizedOperation']:
                    logger.warning(f"Access denied when checking support cases: {e}")
                else:
                    logger.warning(f"Error checking support cases: {e}")
            except Exception as e:
                logger.warning(f"Error with support service: {e}")
        
        # Create finding based on results
        if security_contact_configured:
            status = 'COMPLIANT'
            compliance_status = 'PASS'
            message = 'Security contact information is registered'
        else:
            status = 'NON_COMPLIANT'
            compliance_status = 'FAIL'
            message = 'Security contact information is not registered or not accessible'
        
        finding = {
            'region': region,
            'profile': profile,
            'resource_type': 'AWS Account',
            'resource_id': f'account-contact-{region}',
            'status': status,
            'compliance_status': compliance_status,
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Register security contact information in AWS account'),
            'details': {
                'security_contact_configured': security_contact_configured,
                'contact_details': contact_details,
                'message': message,
                'note': 'This check requires appropriate IAM permissions to access account contact information'
            }
        }
        
        findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in account_security_contact_information_is_registered check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'AWS Account',
            'resource_id': f'account-contact-{region}',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Register security contact information in AWS account'),
            'error': str(e)
        })
        
    return findings

def account_security_contact_information_is_registered(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=account_security_contact_information_is_registered_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = account_security_contact_information_is_registered(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

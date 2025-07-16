#!/usr/bin/env python3
"""
cis_4.0_aws - acm_certificates_expiration_check

Ensure ACM certificates are monitored for expiration
"""

import sys
import os
import json
from datetime import datetime, timezone
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
        'compliance_name': 'cis_4.0_aws',
        'function_name': 'acm_certificates_expiration_check',
        'id': 'acm-cert-expiration',
        'name': 'ACM Certificate Expiration Check',
        'description': 'Ensure ACM certificates are monitored for expiration',
        'api_function': 'client = boto3.client(\'acm\')',
        'user_function': 'list_certificates(), describe_certificate()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Monitor ACM certificates for expiration and renew before expiry'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('acm_certificates_expiration_check')

def acm_certificates_expiration_check_check(acm_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for acm_certificates_expiration_check.
    
    Args:
        acm_client: Boto3 acm client (auto-created by framework)
        region (str): AWS region (auto-managed by framework)
        profile (str): AWS profile name (auto-managed by framework)
        logger: Logger instance (auto-configured by framework)
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    try:
        # Get all certificates
        response = acm_client.list_certificates()
        certificates = response.get('CertificateSummaryList', [])
        
        if not certificates:
            # No certificates found - create a finding indicating no resources
            findings.append({
                'region': region,
                'profile': profile,
                'resource_type': 'AWS::ACM::Certificate',
                'resource_id': 'No certificates found',
                'status': 'COMPLIANT',
                'compliance_status': 'PASS',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                'recommendation': COMPLIANCE_DATA.get('recommendation', 'Monitor ACM certificates for expiration and renew before expiry'),
                'details': {
                    'message': 'No ACM certificates found in this region'
                }
            })
            return findings
        
        current_time = datetime.now(timezone.utc)
        
        for cert_summary in certificates:
            cert_arn = cert_summary.get('CertificateArn')
            domain_name = cert_summary.get('DomainName', 'Unknown')
            
            try:
                # Get detailed certificate information
                cert_response = acm_client.describe_certificate(CertificateArn=cert_arn)
                cert_details = cert_response.get('Certificate', {})
                
                not_after = cert_details.get('NotAfter')
                not_before = cert_details.get('NotBefore')
                status = cert_details.get('Status', 'UNKNOWN')
                cert_type = cert_details.get('Type', 'UNKNOWN')
                renewal_eligibility = cert_details.get('RenewalEligibility', 'UNKNOWN')
                
                # Calculate days until expiration
                days_until_expiry = None
                is_expired = False
                is_expiring_soon = False
                
                if not_after:
                    time_diff = not_after - current_time
                    days_until_expiry = time_diff.days
                    is_expired = days_until_expiry < 0
                    is_expiring_soon = 0 <= days_until_expiry <= 30  # Expiring within 30 days
                
                # Determine compliance status
                # Certificate is non-compliant if:
                # 1. It's expired
                # 2. It's expiring soon (within 30 days) and not eligible for auto-renewal
                # 3. Status is not ISSUED
                
                is_compliant = True
                compliance_issues = []
                
                if is_expired:
                    is_compliant = False
                    compliance_issues.append("Certificate is expired")
                elif is_expiring_soon and renewal_eligibility != 'ELIGIBLE':
                    is_compliant = False
                    compliance_issues.append("Certificate expiring soon and not eligible for auto-renewal")
                elif status != 'ISSUED':
                    is_compliant = False
                    compliance_issues.append(f"Certificate status is {status}, not ISSUED")
                
                findings.append({
                    'region': region,
                    'profile': profile,
                    'resource_type': 'AWS::ACM::Certificate',
                    'resource_id': cert_arn,
                    'status': 'COMPLIANT' if is_compliant else 'NON_COMPLIANT',
                    'compliance_status': 'PASS' if is_compliant else 'FAIL',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Monitor ACM certificates for expiration and renew before expiry'),
                    'details': {
                        'domain_name': domain_name,
                        'certificate_arn': cert_arn,
                        'status': status,
                        'type': cert_type,
                        'not_before': not_before.isoformat() if not_before else None,
                        'not_after': not_after.isoformat() if not_after else None,
                        'days_until_expiry': days_until_expiry,
                        'is_expired': is_expired,
                        'is_expiring_soon': is_expiring_soon,
                        'renewal_eligibility': renewal_eligibility,
                        'compliance_issues': compliance_issues
                    }
                })
                
            except Exception as cert_error:
                logger.error(f"Error getting certificate details for {cert_arn}: {cert_error}")
                findings.append({
                    'region': region,
                    'profile': profile,
                    'resource_type': 'AWS::ACM::Certificate',
                    'resource_id': cert_arn,
                    'status': 'ERROR',
                    'compliance_status': 'ERROR',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Monitor ACM certificates for expiration and renew before expiry'),
                    'error': str(cert_error),
                    'details': {
                        'domain_name': domain_name
                    }
                })
        
    except Exception as e:
        logger.error(f"Error in acm_certificates_expiration_check check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'AWS::ACM::Certificate',
            'resource_id': 'Unknown',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Monitor ACM certificates for expiration and renew before expiry'),
            'error': str(e)
        })
        
    return findings

def acm_certificates_expiration_check(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=acm_certificates_expiration_check_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = acm_certificates_expiration_check(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

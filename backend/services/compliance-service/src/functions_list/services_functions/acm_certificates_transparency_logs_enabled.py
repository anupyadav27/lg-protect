#!/usr/bin/env python3
"""
cis_4.0_aws - acm_certificates_transparency_logs_enabled

Ensure ACM certificates have transparency logs enabled
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
        'compliance_name': 'cis_4.0_aws',
        'function_name': 'acm_certificates_transparency_logs_enabled',
        'id': 'acm-cert-transparency',
        'name': 'ACM Certificate Transparency Logs',
        'description': 'Ensure ACM certificates have transparency logs enabled',
        'api_function': 'client = boto3.client(\'acm\')',
        'user_function': 'list_certificates(), describe_certificate()',
        'risk_level': 'LOW',
        'recommendation': 'Enable certificate transparency logs for ACM certificates'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('acm_certificates_transparency_logs_enabled')

def acm_certificates_transparency_logs_enabled_check(acm_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for acm_certificates_transparency_logs_enabled.
    
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
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'LOW'),
                'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable certificate transparency logs for ACM certificates'),
                'details': {
                    'message': 'No ACM certificates found in this region'
                }
            })
            return findings
        
        for cert_summary in certificates:
            cert_arn = cert_summary.get('CertificateArn')
            domain_name = cert_summary.get('DomainName', 'Unknown')
            
            try:
                # Get detailed certificate information
                cert_response = acm_client.describe_certificate(CertificateArn=cert_arn)
                cert_details = cert_response.get('Certificate', {})
                
                status = cert_details.get('Status', 'UNKNOWN')
                cert_type = cert_details.get('Type', 'UNKNOWN')
                options = cert_details.get('Options', {})
                
                # Check if certificate transparency logging is enabled
                # By default, ACM certificates have CT logging enabled unless explicitly disabled
                ct_logging_enabled = options.get('CertificateTransparencyLoggingPreference', 'ENABLED') == 'ENABLED'
                
                # Certificate is compliant if CT logging is enabled
                is_compliant = ct_logging_enabled
                
                findings.append({
                    'region': region,
                    'profile': profile,
                    'resource_type': 'AWS::ACM::Certificate',
                    'resource_id': cert_arn,
                    'status': 'COMPLIANT' if is_compliant else 'NON_COMPLIANT',
                    'compliance_status': 'PASS' if is_compliant else 'FAIL',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'LOW'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable certificate transparency logs for ACM certificates'),
                    'details': {
                        'domain_name': domain_name,
                        'certificate_arn': cert_arn,
                        'status': status,
                        'type': cert_type,
                        'ct_logging_enabled': ct_logging_enabled,
                        'ct_logging_preference': options.get('CertificateTransparencyLoggingPreference', 'Default (ENABLED)')
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
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'LOW'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable certificate transparency logs for ACM certificates'),
                    'error': str(cert_error),
                    'details': {
                        'domain_name': domain_name
                    }
                })
        
    except Exception as e:
        logger.error(f"Error in acm_certificates_transparency_logs_enabled check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'AWS::ACM::Certificate',
            'resource_id': 'Unknown',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'LOW'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable certificate transparency logs for ACM certificates'),
            'error': str(e)
        })
        
    return findings

def acm_certificates_transparency_logs_enabled(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=acm_certificates_transparency_logs_enabled_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = acm_certificates_transparency_logs_enabled(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

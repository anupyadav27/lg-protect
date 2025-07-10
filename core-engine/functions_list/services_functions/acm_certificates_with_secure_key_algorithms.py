#!/usr/bin/env python3
"""
pci_4.0_aws - acm_certificates_with_secure_key_algorithms

Checks if RSA certificates managed by AWS Certificate Manager (ACM) have a key length of at least '2048' bits
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
                    'recommendation': entry.get('Recommendation', 'Use RSA certificates with key length of at least 2048 bits')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'pci_4.0_aws',
        'function_name': 'acm_certificates_with_secure_key_algorithms',
        'id': '4.1.1',
        'name': 'Strong cryptography and security protocols',
        'description': 'Checks if RSA certificates managed by AWS Certificate Manager (ACM) have a key length of at least \'2048\' bits',
        'api_function': 'client=boto3.client(\'acm\')',
        'user_function': 'list_certificates(), describe_certificate()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Use RSA certificates with key length of at least 2048 bits'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('acm_certificates_with_secure_key_algorithms')

def acm_certificates_with_secure_key_algorithms_check(acm_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for acm_certificates_with_secure_key_algorithms.
    
    Args:
        acm_client: Boto3 ACM client (auto-created by framework)
        region (str): AWS region (auto-managed by framework)
        profile (str): AWS profile name (auto-managed by framework)
        logger: Logger instance (auto-configured by framework)
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    try:
        # List all certificates
        response = acm_client.list_certificates()
        certificates = response.get('CertificateSummaryList', [])
        
        if not certificates:
            logger.info(f"No ACM certificates found in region {region}")
            return findings
        
        for cert_summary in certificates:
            cert_arn = cert_summary['CertificateArn']
            domain_name = cert_summary['DomainName']
            
            try:
                # Get detailed certificate information
                cert_details = acm_client.describe_certificate(CertificateArn=cert_arn)
                certificate = cert_details['Certificate']
                
                key_algorithm = certificate.get('KeyAlgorithm', 'Unknown')
                key_usage = certificate.get('KeyUsages', [])
                status = certificate.get('Status', 'Unknown')
                
                # Check if it's an RSA certificate and get key size
                if key_algorithm.startswith('RSA'):
                    # Extract key size from algorithm (e.g., "RSA-2048" -> 2048)
                    try:
                        key_size = int(key_algorithm.split('-')[1])
                    except (IndexError, ValueError):
                        key_size = 0
                        logger.warning(f"Could not parse key size from algorithm: {key_algorithm}")
                    
                    # Check if key size is at least 2048 bits
                    if key_size >= 2048:
                        compliance_status = 'PASS'
                        cert_status = 'COMPLIANT'
                    else:
                        compliance_status = 'FAIL'
                        cert_status = 'NON_COMPLIANT'
                else:
                    # Non-RSA certificates (EC, etc.) are considered compliant for this check
                    compliance_status = 'PASS'
                    cert_status = 'COMPLIANT'
                    key_size = None
                
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'ACM Certificate',
                    'resource_id': cert_arn,
                    'status': cert_status,
                    'compliance_status': compliance_status,
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Use RSA certificates with key length of at least 2048 bits'),
                    'details': {
                        'certificate_arn': cert_arn,
                        'domain_name': domain_name,
                        'key_algorithm': key_algorithm,
                        'key_size': key_size,
                        'certificate_status': status,
                        'key_usages': [usage.get('Name') for usage in key_usage],
                        'subject': certificate.get('Subject'),
                        'issuer': certificate.get('Issuer'),
                        'created_at': certificate.get('CreatedAt').isoformat() if certificate.get('CreatedAt') else None,
                        'not_before': certificate.get('NotBefore').isoformat() if certificate.get('NotBefore') else None,
                        'not_after': certificate.get('NotAfter').isoformat() if certificate.get('NotAfter') else None
                    }
                }
                
                findings.append(finding)
                
            except Exception as e:
                logger.error(f"Error describing certificate {cert_arn}: {e}")
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'ACM Certificate',
                    'resource_id': cert_arn,
                    'status': 'ERROR',
                    'compliance_status': 'ERROR',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Use RSA certificates with key length of at least 2048 bits'),
                    'error': f"Error describing certificate: {str(e)}"
                }
                findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in acm_certificates_with_secure_key_algorithms check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'ACM Certificate',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Use RSA certificates with key length of at least 2048 bits'),
            'error': str(e)
        })
        
    return findings

def acm_certificates_with_secure_key_algorithms(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=acm_certificates_with_secure_key_algorithms_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = acm_certificates_with_secure_key_algorithms(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

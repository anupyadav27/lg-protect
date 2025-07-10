#!/usr/bin/env python3
"""
pci_4.0_aws - trustedadvisor_errors_and_warnings

Implement security testing procedures to validate that security controls operate as expected.
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
        'compliance_name': 'pci_4.0_aws',
        'function_name': 'trustedadvisor_errors_and_warnings',
        'id': 'TA-001',
        'name': 'TrustedAdvisor Errors and Warnings',
        'description': 'Implement security testing procedures to validate that security controls operate as expected.',
        'api_function': 'client=boto3.client("support")',
        'user_function': 'describe_trusted_advisor_checks(), describe_trusted_advisor_check_result()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Review and address TrustedAdvisor security findings and warnings'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('trustedadvisor_errors_and_warnings')

def trustedadvisor_errors_and_warnings_check(support_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for trustedadvisor_errors_and_warnings.
    
    Args:
        support_client: Boto3 Support client (auto-created by framework)
        region (str): AWS region (auto-managed by framework)
        profile (str): AWS profile name (auto-managed by framework)
        logger: Logger instance (auto-configured by framework)
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    try:
        # Note: TrustedAdvisor checks are only available in us-east-1 region
        # and require Business or Enterprise support plan
        if region != 'us-east-1':
            logger.info(f"TrustedAdvisor checks are only available in us-east-1, skipping region {region}")
            return findings
        
        # Get all available TrustedAdvisor checks
        try:
            checks_response = support_client.describe_trusted_advisor_checks(language='en')
            checks = checks_response.get('checks', [])
        except Exception as e:
            if 'SubscriptionRequiredException' in str(e):
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'TrustedAdvisor_Access',
                    'resource_id': 'Support Plan Required',
                    'status': 'NON_COMPLIANT',
                    'compliance_status': 'FAIL',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                    'recommendation': 'Upgrade to Business or Enterprise support plan to access TrustedAdvisor',
                    'details': {
                        'issue': 'Business or Enterprise support plan required for TrustedAdvisor access',
                        'error': str(e)
                    }
                }
                findings.append(finding)
                return findings
            else:
                raise e
        
        # Filter for security-related checks
        security_checks = []
        for check in checks:
            check_name = check.get('name', '').lower()
            category = check.get('category', '').lower()
            if 'security' in category or any(keyword in check_name for keyword in 
                ['security', 'iam', 'mfa', 'access', 'encryption', 'ssl', 'certificate']):
                security_checks.append(check)
        
        if not security_checks:
            logger.info("No security-related TrustedAdvisor checks found")
            return findings
        
        # Check the status of security-related checks
        error_count = 0
        warning_count = 0
        ok_count = 0
        check_results = []
        
        for check in security_checks:
            check_id = check.get('id')
            check_name = check.get('name')
            check_description = check.get('description', '')
            check_category = check.get('category', '')
            
            try:
                # Get the check result
                result_response = support_client.describe_trusted_advisor_check_result(
                    checkId=check_id,
                    language='en'
                )
                
                result = result_response.get('result', {})
                status = result.get('status', 'unknown')
                timestamp = result.get('timestamp', 'Unknown')
                
                check_result = {
                    'check_id': check_id,
                    'check_name': check_name,
                    'check_description': check_description,
                    'check_category': check_category,
                    'status': status,
                    'timestamp': timestamp
                }
                
                # Count status types
                if status == 'error':
                    error_count += 1
                elif status == 'warning':
                    warning_count += 1
                elif status == 'ok':
                    ok_count += 1
                
                # Get flagged resources if available
                flagged_resources = result.get('flaggedResources', [])
                if flagged_resources:
                    check_result['flagged_resources_count'] = len(flagged_resources)
                    check_result['sample_flagged_resources'] = flagged_resources[:5]  # First 5 as sample
                
                check_results.append(check_result)
                
            except Exception as check_error:
                logger.warning(f"Could not get result for TrustedAdvisor check {check_name}: {check_error}")
                check_result = {
                    'check_id': check_id,
                    'check_name': check_name,
                    'check_description': check_description,
                    'check_category': check_category,
                    'status': 'error',
                    'error': str(check_error)
                }
                check_results.append(check_result)
                error_count += 1
        
        # Determine overall compliance
        # Compliant if no errors and minimal warnings
        is_compliant = error_count == 0 and warning_count <= 2
        
        if is_compliant:
            # No significant issues found - COMPLIANT
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'TrustedAdvisor_SecurityChecks',
                'resource_id': 'Security Checks Summary',
                'status': 'COMPLIANT',
                'compliance_status': 'PASS',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                'recommendation': COMPLIANCE_DATA.get('recommendation', 'Continue monitoring TrustedAdvisor recommendations'),
                'details': {
                    'total_security_checks': len(security_checks),
                    'checks_ok': ok_count,
                    'checks_warning': warning_count,
                    'checks_error': error_count,
                    'check_results': check_results
                }
            }
        else:
            # Errors or too many warnings found - NON_COMPLIANT
            issues = []
            if error_count > 0:
                issues.append(f'{error_count} security checks with errors')
            if warning_count > 2:
                issues.append(f'{warning_count} security checks with warnings')
            
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'TrustedAdvisor_SecurityChecks',
                'resource_id': 'Security Checks Summary',
                'status': 'NON_COMPLIANT',
                'compliance_status': 'FAIL',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                'recommendation': 'Review and address TrustedAdvisor security findings',
                'details': {
                    'total_security_checks': len(security_checks),
                    'checks_ok': ok_count,
                    'checks_warning': warning_count,
                    'checks_error': error_count,
                    'issues': issues,
                    'check_results': check_results
                }
            }
        
        findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in trustedadvisor_errors_and_warnings check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'TrustedAdvisor_SecurityChecks',
            'status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Review TrustedAdvisor configuration'),
            'error': str(e)
        })
        
    return findings

def trustedadvisor_errors_and_warnings(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=trustedadvisor_errors_and_warnings_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = trustedadvisor_errors_and_warnings(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

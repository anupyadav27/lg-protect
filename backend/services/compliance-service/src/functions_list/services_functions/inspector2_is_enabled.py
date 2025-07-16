#!/usr/bin/env python3
"""
aws_foundational_technical_review_aws - inspector2_is_enabled

Define a mechanism and frequency to scan and patch for vulnerabilities in your dependencies, and in your operating systems to help protect against new threats. Scan and patch your dependencies, and your operating systems on a defined schedule. Software vulnerability management is essential to keeping your system secure from threat actors. Embedding vulnerability assessments early into your continuous integration/continuous delivery (CI/CD) pipeline allows you to prioritize remediation of any security vulnerabilities detected. The solution you need to achieve this varies according to the AWS services that you are consuming. To check for vulnerabilities in software running in Amazon EC2 instances, you can add Amazon Inspector to your pipeline to cause your build to fail if Inspector detects vulnerabilities. You can also use open source products such as OWASP Dependency-Check, Snyk, OpenVAS, package managers and AWS Partner tools for vulnerability management.
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
        'compliance_name': 'aws_foundational_technical_review_aws',
        'function_name': 'inspector2_is_enabled',
        'id': 'inspector2_is_enabled',
        'name': 'Inspector2 Service Enabled Check',
        'description': 'Define a mechanism and frequency to scan and patch for vulnerabilities in your dependencies, and in your operating systems to help protect against new threats.',
        'api_function': 'client = boto3.client("inspector2")',
        'user_function': 'get_status()',
        'risk_level': 'HIGH',
        'recommendation': 'Enable Amazon Inspector2 to scan for vulnerabilities in your EC2 instances and container images'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('inspector2_is_enabled')

def inspector2_is_enabled_check(inspector2_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for inspector2_is_enabled.
    
    Args:
        inspector2_client: Boto3 Inspector2 service client (auto-created by framework)
        region (str): AWS region (auto-managed by framework)
        profile (str): AWS profile name (auto-managed by framework)
        logger: Logger instance (auto-configured by framework)
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    try:
        # Get Inspector2 status for the account
        response = inspector2_client.get_status()
        
        # Check if any resource types are enabled
        accounts = response.get('accounts', [])
        
        if not accounts:
            # No accounts configured - Inspector2 is not enabled
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'Inspector2 Service',
                'resource_id': f'inspector2-{region}',
                'status': 'NON_COMPLIANT',
                'compliance_status': 'FAIL',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable Amazon Inspector2 to scan for vulnerabilities'),
                'details': {
                    'service_status': 'DISABLED',
                    'enabled_resource_types': [],
                    'reason': 'Inspector2 is not configured for any accounts'
                }
            }
            findings.append(finding)
        else:
            # Process each account
            for account in accounts:
                account_id = account.get('accountId', 'unknown')
                resource_state = account.get('resourceState', {})
                
                # Check which resource types are enabled
                enabled_types = []
                for resource_type, state in resource_state.items():
                    if state.get('status') == 'ENABLED':
                        enabled_types.append(resource_type)
                
                if enabled_types:
                    # Inspector2 is enabled for some resource types - COMPLIANT
                    finding = {
                        'region': region,
                        'profile': profile,
                        'resource_type': 'Inspector2 Service',
                        'resource_id': f'inspector2-{account_id}-{region}',
                        'status': 'COMPLIANT',
                        'compliance_status': 'PASS',
                        'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                        'recommendation': 'Inspector2 is properly enabled',
                        'details': {
                            'account_id': account_id,
                            'service_status': 'ENABLED',
                            'enabled_resource_types': enabled_types,
                            'resource_state': resource_state
                        }
                    }
                else:
                    # Inspector2 is not enabled for any resource types - NON_COMPLIANT
                    finding = {
                        'region': region,
                        'profile': profile,
                        'resource_type': 'Inspector2 Service',
                        'resource_id': f'inspector2-{account_id}-{region}',
                        'status': 'NON_COMPLIANT',
                        'compliance_status': 'FAIL',
                        'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                        'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable Amazon Inspector2 to scan for vulnerabilities'),
                        'details': {
                            'account_id': account_id,
                            'service_status': 'DISABLED',
                            'enabled_resource_types': [],
                            'resource_state': resource_state,
                            'reason': 'No resource types are enabled for Inspector2'
                        }
                    }
                
                findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in inspector2_is_enabled check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'Inspector2 Service',
            'resource_id': f'inspector2-{region}',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable Amazon Inspector2 to scan for vulnerabilities'),
            'error': str(e),
            'details': {
                'error_type': type(e).__name__,
                'error_message': str(e)
            }
        })
        
    return findings

def inspector2_is_enabled(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=inspector2_is_enabled_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = inspector2_is_enabled(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

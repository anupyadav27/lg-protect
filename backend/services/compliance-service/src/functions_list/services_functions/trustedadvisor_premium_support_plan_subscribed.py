#!/usr/bin/env python3
"""
pci_4.0_aws - trustedadvisor_premium_support_plan_subscribed

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
        'function_name': 'trustedadvisor_premium_support_plan_subscribed',
        'id': 'TA-002',
        'name': 'TrustedAdvisor Premium Support Plan',
        'description': 'Implement security testing procedures to validate that security controls operate as expected.',
        'api_function': 'client=boto3.client("support")',
        'user_function': 'describe_trusted_advisor_checks()',
        'risk_level': 'LOW',
        'recommendation': 'Subscribe to Business or Enterprise support plan for enhanced security monitoring'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('trustedadvisor_premium_support_plan_subscribed')

def trustedadvisor_premium_support_plan_subscribed_check(support_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for trustedadvisor_premium_support_plan_subscribed.
    
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
        # Note: TrustedAdvisor API calls are only available in us-east-1 region
        if region != 'us-east-1':
            logger.info(f"TrustedAdvisor API is only available in us-east-1, skipping region {region}")
            return findings
        
        # Try to access TrustedAdvisor checks to determine support plan level
        try:
            # Attempt to call describe_trusted_advisor_checks
            checks_response = support_client.describe_trusted_advisor_checks(language='en')
            checks = checks_response.get('checks', [])
            
            # If we can access checks, we have at least Business support
            # Count different categories of checks to determine plan level
            security_checks = 0
            performance_checks = 0
            cost_optimization_checks = 0
            fault_tolerance_checks = 0
            service_limits_checks = 0
            
            for check in checks:
                category = check.get('category', '').lower()
                if 'security' in category:
                    security_checks += 1
                elif 'performance' in category:
                    performance_checks += 1
                elif 'cost' in category:
                    cost_optimization_checks += 1
                elif 'fault' in category or 'tolerance' in category:
                    fault_tolerance_checks += 1
                elif 'service' in category or 'limit' in category:
                    service_limits_checks += 1
            
            total_checks = len(checks)
            
            # Determine support plan level based on available checks
            # Basic/Developer: Limited or no TrustedAdvisor access
            # Business: Core checks (usually 50+ checks)
            # Enterprise: Full set of checks (usually 100+ checks)
            if total_checks >= 100:
                support_level = 'Enterprise'
                is_premium = True
            elif total_checks >= 50:
                support_level = 'Business'
                is_premium = True
            else:
                support_level = 'Basic/Developer'
                is_premium = False
            
            if is_premium:
                # Premium support plan detected - COMPLIANT
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'Support_Plan',
                    'resource_id': 'AWS Support Plan',
                    'status': 'COMPLIANT',
                    'compliance_status': 'PASS',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'LOW'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Continue utilizing premium support features'),
                    'details': {
                        'support_level': support_level,
                        'has_premium_support': True,
                        'total_trusted_advisor_checks': total_checks,
                        'security_checks_available': security_checks,
                        'performance_checks_available': performance_checks,
                        'cost_optimization_checks_available': cost_optimization_checks,
                        'fault_tolerance_checks_available': fault_tolerance_checks,
                        'service_limits_checks_available': service_limits_checks,
                        'trusted_advisor_accessible': True
                    }
                }
            else:
                # Basic support plan detected - NON_COMPLIANT
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'Support_Plan',
                    'resource_id': 'AWS Support Plan',
                    'status': 'NON_COMPLIANT',
                    'compliance_status': 'FAIL',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'LOW'),
                    'recommendation': 'Upgrade to Business or Enterprise support plan for enhanced security monitoring',
                    'details': {
                        'support_level': support_level,
                        'has_premium_support': False,
                        'total_trusted_advisor_checks': total_checks,
                        'security_checks_available': security_checks,
                        'trusted_advisor_accessible': True,
                        'limitation': 'Limited TrustedAdvisor functionality with basic support'
                    }
                }
            
        except Exception as e:
            error_str = str(e)
            
            if 'SubscriptionRequiredException' in error_str or 'InvalidParameterValueException' in error_str:
                # Basic support plan - cannot access TrustedAdvisor - NON_COMPLIANT
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'Support_Plan',
                    'resource_id': 'AWS Support Plan',
                    'status': 'NON_COMPLIANT',
                    'compliance_status': 'FAIL',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'LOW'),
                    'recommendation': 'Upgrade to Business or Enterprise support plan to access TrustedAdvisor',
                    'details': {
                        'support_level': 'Basic/Developer',
                        'has_premium_support': False,
                        'trusted_advisor_accessible': False,
                        'error_type': 'Access Denied',
                        'limitation': 'TrustedAdvisor requires Business or Enterprise support plan'
                    }
                }
            else:
                # Other error - treat as ERROR
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'Support_Plan',
                    'resource_id': 'AWS Support Plan',
                    'status': 'ERROR',
                    'compliance_status': 'ERROR',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'LOW'),
                    'recommendation': 'Review AWS Support configuration',
                    'error': error_str,
                    'details': {
                        'error_type': 'API Error',
                        'trusted_advisor_accessible': False
                    }
                }
        
        findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in trustedadvisor_premium_support_plan_subscribed check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'Support_Plan',
            'status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'LOW'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Review AWS Support configuration'),
            'error': str(e)
        })
        
    return findings

def trustedadvisor_premium_support_plan_subscribed(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=trustedadvisor_premium_support_plan_subscribed_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = trustedadvisor_premium_support_plan_subscribed(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

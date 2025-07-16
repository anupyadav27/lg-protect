#!/usr/bin/env python3
"""
pci_4.0_aws - wafv2_webacl_with_rules

Checks if a WAFv2 Web ACL contains any WAF rules or WAF rule groups
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
        'function_name': 'wafv2_webacl_with_rules',
        'id': 'WAF-003',
        'name': 'WAFv2 Web ACL Rules Configuration',
        'description': 'Checks if a WAFv2 Web ACL contains any WAF rules or WAF rule groups',
        'api_function': 'client=boto3.client("wafv2")',
        'user_function': 'get_web_acl()',
        'risk_level': 'HIGH',
        'recommendation': 'Ensure all WAFv2 Web ACLs contain appropriate rules or rule groups'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('wafv2_webacl_with_rules')

def wafv2_webacl_with_rules_check(wafv2_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for wafv2_webacl_with_rules.
    
    Args:
        wafv2_client: Boto3 WAFv2 client (auto-created by framework)
        region (str): AWS region (auto-managed by framework)
        profile (str): AWS profile name (auto-managed by framework)
        logger: Logger instance (auto-configured by framework)
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    try:
        # Get all Web ACLs for both CLOUDFRONT and REGIONAL scopes
        scopes = ['CLOUDFRONT', 'REGIONAL']
        
        for scope in scopes:
            try:
                # List Web ACLs for this scope
                response = wafv2_client.list_web_acls(Scope=scope)
                web_acls = response.get('WebACLs', [])
                
                for web_acl in web_acls:
                    web_acl_id = web_acl.get('Id', 'Unknown')
                    web_acl_name = web_acl.get('Name', 'Unknown')
                    
                    try:
                        # Get detailed Web ACL information including rules
                        web_acl_response = wafv2_client.get_web_acl(
                            Scope=scope,
                            Id=web_acl_id,
                            Name=web_acl_name
                        )
                        
                        web_acl_details = web_acl_response.get('WebACL', {})
                        rules = web_acl_details.get('Rules', [])
                        default_action = web_acl_details.get('DefaultAction', {})
                        
                        # Count different types of rules
                        rule_count = len(rules)
                        managed_rule_groups = []
                        custom_rules = []
                        rate_based_rules = []
                        
                        for rule in rules:
                            rule_name = rule.get('Name', 'Unknown')
                            statement = rule.get('Statement', {})
                            
                            if 'ManagedRuleGroupStatement' in statement:
                                managed_rule_groups.append(rule_name)
                            elif 'RateBasedStatement' in statement:
                                rate_based_rules.append(rule_name)
                            else:
                                custom_rules.append(rule_name)
                        
                        if rule_count > 0:
                            # Web ACL has rules - COMPLIANT
                            finding = {
                                'region': region,
                                'profile': profile,
                                'resource_type': 'WAFv2_WebACL',
                                'resource_id': f"{web_acl_name} ({web_acl_id})",
                                'status': 'COMPLIANT',
                                'compliance_status': 'PASS',
                                'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                                'recommendation': COMPLIANCE_DATA.get('recommendation', 'Maintain rule configuration'),
                                'details': {
                                    'web_acl_name': web_acl_name,
                                    'web_acl_id': web_acl_id,
                                    'scope': scope,
                                    'total_rules': rule_count,
                                    'managed_rule_groups': len(managed_rule_groups),
                                    'custom_rules': len(custom_rules),
                                    'rate_based_rules': len(rate_based_rules),
                                    'default_action': list(default_action.keys())[0] if default_action else 'Unknown',
                                    'rule_names': [rule.get('Name', 'Unknown') for rule in rules]
                                }
                            }
                        else:
                            # Web ACL has no rules - NON_COMPLIANT
                            finding = {
                                'region': region,
                                'profile': profile,
                                'resource_type': 'WAFv2_WebACL',
                                'resource_id': f"{web_acl_name} ({web_acl_id})",
                                'status': 'NON_COMPLIANT',
                                'compliance_status': 'FAIL',
                                'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                                'recommendation': 'Add rules or rule groups to this Web ACL',
                                'details': {
                                    'web_acl_name': web_acl_name,
                                    'web_acl_id': web_acl_id,
                                    'scope': scope,
                                    'total_rules': 0,
                                    'default_action': list(default_action.keys())[0] if default_action else 'Unknown',
                                    'issue': 'Web ACL contains no rules or rule groups'
                                }
                            }
                            
                    except Exception as web_acl_error:
                        logger.error(f"Error getting Web ACL details for {web_acl_id}: {web_acl_error}")
                        finding = {
                            'region': region,
                            'profile': profile,
                            'resource_type': 'WAFv2_WebACL',
                            'resource_id': f"{web_acl_name} ({web_acl_id})",
                            'status': 'ERROR',
                            'compliance_status': 'ERROR',
                            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                            'recommendation': 'Review Web ACL configuration',
                            'error': str(web_acl_error),
                            'details': {
                                'web_acl_name': web_acl_name,
                                'web_acl_id': web_acl_id,
                                'scope': scope
                            }
                        }
                    
                    findings.append(finding)
                    
            except Exception as scope_error:
                logger.error(f"Error listing Web ACLs for scope {scope}: {scope_error}")
                continue
        
    except Exception as e:
        logger.error(f"Error in wafv2_webacl_with_rules check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'WAFv2_WebACL',
            'status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Review WAFv2 configuration'),
            'error': str(e)
        })
        
    return findings

def wafv2_webacl_with_rules(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=wafv2_webacl_with_rules_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = wafv2_webacl_with_rules(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

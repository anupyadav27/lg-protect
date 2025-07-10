#!/usr/bin/env python3
"""
pci_4.0_aws - waf_regional_webacl_with_rules

Checks if a WAF regional Web ACL contains any WAF rules or rule groups
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
                    'risk_level': entry.get('Risk Level', 'HIGH'),
                    'recommendation': entry.get('Recommendation', 'Configure WAF regional WebACLs with appropriate rules to protect against web application attacks')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'pci_4.0_aws',
        'function_name': 'waf_regional_webacl_with_rules',
        'id': 'PCI_WAF_REGIONAL_WEBACL',
        'name': 'WAF Regional WebACL Rules Check',
        'description': 'Checks if a WAF regional Web ACL contains any WAF rules or rule groups',
        'api_function': 'client=boto3.client(\'waf-regional\')',
        'user_function': 'get_web_acl()',
        'risk_level': 'HIGH',
        'recommendation': 'Configure WAF regional WebACLs with appropriate rules to protect against web application attacks'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('waf_regional_webacl_with_rules')

def waf_regional_webacl_with_rules_check(wafv2_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for waf_regional_webacl_with_rules.
    
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
        # List WebACLs with REGIONAL scope
        webacls_response = wafv2_client.list_web_acls(Scope='REGIONAL')
        webacls = webacls_response.get('WebACLs', [])
        
        if not webacls:
            logger.info(f"No regional WAF WebACLs found in region {region}")
            return findings
        
        for webacl_summary in webacls:
            webacl_name = webacl_summary.get('Name', '')
            webacl_id = webacl_summary.get('Id', '')
            webacl_arn = webacl_summary.get('ARN', '')
            
            try:
                # Get detailed WebACL information
                webacl_response = wafv2_client.get_web_acl(
                    Name=webacl_name,
                    Id=webacl_id,
                    Scope='REGIONAL'
                )
                
                webacl_details = webacl_response.get('WebACL', {})
                rules = webacl_details.get('Rules', [])
                default_action = webacl_details.get('DefaultAction', {})
                
                # Check if WebACL has rules
                has_rules = len(rules) > 0
                rule_count = len(rules)
                
                # Analyze rule types and actions
                rule_types = []
                rule_actions = []
                managed_rule_groups = []
                
                for rule in rules:
                    # Get rule action
                    action = rule.get('Action', {})
                    if 'Allow' in action:
                        rule_actions.append('Allow')
                    elif 'Block' in action:
                        rule_actions.append('Block')
                    elif 'Count' in action:
                        rule_actions.append('Count')
                    else:
                        rule_actions.append('Other')
                    
                    # Get rule statement types
                    statement = rule.get('Statement', {})
                    if 'ManagedRuleGroupStatement' in statement:
                        rule_types.append('ManagedRuleGroup')
                        vendor_name = statement['ManagedRuleGroupStatement'].get('VendorName', '')
                        group_name = statement['ManagedRuleGroupStatement'].get('Name', '')
                        managed_rule_groups.append(f"{vendor_name}:{group_name}")
                    elif 'RuleGroupReferenceStatement' in statement:
                        rule_types.append('RuleGroupReference')
                    elif 'IPSetReferenceStatement' in statement:
                        rule_types.append('IPSetReference')
                    elif 'ByteMatchStatement' in statement:
                        rule_types.append('ByteMatch')
                    elif 'GeoMatchStatement' in statement:
                        rule_types.append('GeoMatch')
                    elif 'RateLimitStatement' in statement:
                        rule_types.append('RateLimit')
                    else:
                        rule_types.append('Other')
                
                # Determine default action
                default_action_type = 'Allow' if 'Allow' in default_action else 'Block'
                
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'WAFv2WebACL',
                    'resource_id': webacl_arn,
                    'status': 'COMPLIANT' if has_rules else 'NON_COMPLIANT',
                    'compliance_status': 'PASS' if has_rules else 'FAIL',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Configure WAF regional WebACLs with appropriate rules'),
                    'details': {
                        'webacl_name': webacl_name,
                        'webacl_id': webacl_id,
                        'webacl_arn': webacl_arn,
                        'has_rules': has_rules,
                        'rule_count': rule_count,
                        'rule_types': list(set(rule_types)),
                        'rule_actions': list(set(rule_actions)),
                        'managed_rule_groups': managed_rule_groups,
                        'default_action': default_action_type,
                        'scope': 'REGIONAL',
                        'capacity': webacl_details.get('Capacity', 0),
                        'description': webacl_details.get('Description', ''),
                        'custom_response_bodies': webacl_details.get('CustomResponseBodies', {})
                    }
                }
                
                findings.append(finding)
                
                if has_rules:
                    logger.info(f"WAF regional WebACL {webacl_name} contains {rule_count} rules with default action: {default_action_type}")
                else:
                    logger.warning(f"WAF regional WebACL {webacl_name} has no rules configured (default action: {default_action_type})")
                    
            except Exception as webacl_error:
                logger.error(f"Error checking WebACL {webacl_name}: {webacl_error}")
                findings.append({
                    'region': region,
                    'profile': profile,
                    'resource_type': 'WAFv2WebACL',
                    'resource_id': webacl_arn or webacl_id,
                    'status': 'ERROR',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Configure WAF regional WebACLs with appropriate rules'),
                    'error': str(webacl_error)
                })
        
    except Exception as e:
        logger.error(f"Error in waf_regional_webacl_with_rules check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'WAFv2WebACL',
            'status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Configure WAF regional WebACLs with appropriate rules'),
            'error': str(e)
        })
        
    return findings

def waf_regional_webacl_with_rules(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=waf_regional_webacl_with_rules_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = waf_regional_webacl_with_rules(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

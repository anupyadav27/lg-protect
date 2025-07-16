#!/usr/bin/env python3
"""
pci_4.0_aws - waf_global_rule_with_conditions

Checks if an AWS WAF global rule contains any conditions
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
        compliance_json_path = os.path.join(
            os.path.dirname(__file__), '..', '..', 'compliance_checks.json'
        )
        
        with open(compliance_json_path, 'r') as f:
            compliance_data = json.load(f)
        
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
        
    return {
        'compliance_name': 'pci_4.0_aws',
        'function_name': 'waf_global_rule_with_conditions',
        'id': 'PCI-6.5.10',
        'name': 'WAF global rule should contain conditions',
        'description': 'Checks if an AWS WAF global rule contains any conditions',
        'api_function': 'client = boto3.client("wafv2")',
        'user_function': 'get_rule()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Ensure WAF rules have appropriate conditions configured'
    }

COMPLIANCE_DATA = load_compliance_metadata('waf_global_rule_with_conditions')

def waf_global_rule_with_conditions_check(wafv2_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for waf_global_rule_with_conditions.
    
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
        # List all Web ACLs (global scope for CloudFront)
        web_acls_response = wafv2_client.list_web_acls(Scope='CLOUDFRONT')
        web_acls = web_acls_response.get('WebACLs', [])
        
        for web_acl in web_acls:
            web_acl_name = web_acl.get('Name')
            web_acl_id = web_acl.get('Id')
            
            try:
                # Get detailed Web ACL information
                web_acl_details = wafv2_client.get_web_acl(
                    Name=web_acl_name,
                    Id=web_acl_id,
                    Scope='CLOUDFRONT'
                )
                
                web_acl_info = web_acl_details.get('WebACL', {})
                rules = web_acl_info.get('Rules', [])
                
                for rule in rules:
                    rule_name = rule.get('Name')
                    action = rule.get('Action', {})
                    statement = rule.get('Statement', {})
                    
                    # Check if rule has conditions (statement contains conditions)
                    has_conditions = _check_rule_has_conditions(statement)
                    
                    status = 'COMPLIANT' if has_conditions else 'NON_COMPLIANT'
                    compliance_status = 'PASS' if has_conditions else 'FAIL'
                    
                    finding = {
                        'region': region,
                        'profile': profile,
                        'resource_type': 'WAF_RULE',
                        'resource_id': f"{web_acl_name}:{rule_name}",
                        'status': status,
                        'compliance_status': compliance_status,
                        'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                        'recommendation': COMPLIANCE_DATA.get('recommendation', 'Ensure WAF rules have appropriate conditions configured'),
                        'details': {
                            'web_acl_name': web_acl_name,
                            'web_acl_id': web_acl_id,
                            'rule_name': rule_name,
                            'has_conditions': has_conditions,
                            'action': action,
                            'statement_keys': list(statement.keys()) if statement else []
                        }
                    }
                    
                    findings.append(finding)
                    
            except Exception as web_acl_error:
                logger.warning(f"Could not get details for Web ACL {web_acl_name}: {web_acl_error}")
                continue
        
        # Also check regional Web ACLs
        try:
            regional_web_acls_response = wafv2_client.list_web_acls(Scope='REGIONAL')
            regional_web_acls = regional_web_acls_response.get('WebACLs', [])
            
            for web_acl in regional_web_acls:
                web_acl_name = web_acl.get('Name')
                web_acl_id = web_acl.get('Id')
                
                try:
                    # Get detailed Web ACL information
                    web_acl_details = wafv2_client.get_web_acl(
                        Name=web_acl_name,
                        Id=web_acl_id,
                        Scope='REGIONAL'
                    )
                    
                    web_acl_info = web_acl_details.get('WebACL', {})
                    rules = web_acl_info.get('Rules', [])
                    
                    for rule in rules:
                        rule_name = rule.get('Name')
                        action = rule.get('Action', {})
                        statement = rule.get('Statement', {})
                        
                        # Check if rule has conditions
                        has_conditions = _check_rule_has_conditions(statement)
                        
                        status = 'COMPLIANT' if has_conditions else 'NON_COMPLIANT'
                        compliance_status = 'PASS' if has_conditions else 'FAIL'
                        
                        finding = {
                            'region': region,
                            'profile': profile,
                            'resource_type': 'WAF_RULE',
                            'resource_id': f"{web_acl_name}:{rule_name}",
                            'status': status,
                            'compliance_status': compliance_status,
                            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Ensure WAF rules have appropriate conditions configured'),
                            'details': {
                                'web_acl_name': web_acl_name,
                                'web_acl_id': web_acl_id,
                                'rule_name': rule_name,
                                'scope': 'REGIONAL',
                                'has_conditions': has_conditions,
                                'action': action,
                                'statement_keys': list(statement.keys()) if statement else []
                            }
                        }
                        
                        findings.append(finding)
                        
                except Exception as web_acl_error:
                    logger.warning(f"Could not get details for regional Web ACL {web_acl_name}: {web_acl_error}")
                    continue
                    
        except Exception as regional_error:
            logger.warning(f"Could not list regional Web ACLs: {regional_error}")
        
        # If no rules found, add informational finding
        if not findings:
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'WAF_RULE',
                'resource_id': 'NO_RULES',
                'status': 'COMPLIANT',
                'compliance_status': 'PASS',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                'recommendation': 'No WAF rules found in this region',
                'details': {
                    'message': 'No WAF rules found',
                    'rules_count': 0
                }
            }
            findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in waf_global_rule_with_conditions check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'WAF_RULE',
            'status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Ensure WAF rules have appropriate conditions configured'),
            'error': str(e)
        })
        
    return findings

def _check_rule_has_conditions(statement: dict) -> bool:
    """
    Check if a WAF rule statement has meaningful conditions.
    
    Args:
        statement (dict): The rule statement
        
    Returns:
        bool: True if the rule has conditions, False otherwise
    """
    if not statement:
        return False
    
    # Check for various types of conditions
    condition_keys = [
        'ByteMatchStatement',
        'SqliMatchStatement', 
        'XssMatchStatement',
        'SizeConstraintStatement',
        'GeoMatchStatement',
        'RuleGroupReferenceStatement',
        'IPSetReferenceStatement',
        'RegexPatternSetReferenceStatement',
        'RateBasedStatement',
        'AndStatement',
        'OrStatement',
        'NotStatement'
    ]
    
    # Check if any condition keys are present
    for key in condition_keys:
        if key in statement:
            return True
    
    # Check nested statements
    for key, value in statement.items():
        if isinstance(value, dict):
            if _check_rule_has_conditions(value):
                return True
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict) and _check_rule_has_conditions(item):
                    return True
    
    return False

def waf_global_rule_with_conditions(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=waf_global_rule_with_conditions_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    args = setup_command_line_interface(COMPLIANCE_DATA)
    results = waf_global_rule_with_conditions(
        profile_name=args.profile,
        region_name=args.region
    )
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

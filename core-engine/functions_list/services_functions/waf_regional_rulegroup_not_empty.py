#!/usr/bin/env python3
"""
pci_4.0_aws - waf_regional_rulegroup_not_empty

Checks if WAF Regional rule groups contain any rules
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
                    'recommendation': entry.get('Recommendation', 'Configure WAF regional rule groups with appropriate rules to protect against common attacks')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'pci_4.0_aws',
        'function_name': 'waf_regional_rulegroup_not_empty',
        'id': 'PCI_WAF_REGIONAL_RULES',
        'name': 'WAF Regional Rule Group Check',
        'description': 'Checks if WAF Regional rule groups contain any rules',
        'api_function': 'client=boto3.client(\'waf-regional\')',
        'user_function': 'get_rule_group()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Configure WAF regional rule groups with appropriate rules to protect against common attacks'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('waf_regional_rulegroup_not_empty')

def waf_regional_rulegroup_not_empty_check(wafv2_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for waf_regional_rulegroup_not_empty.
    
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
        # List rule groups with REGIONAL scope
        rule_groups_response = wafv2_client.list_rule_groups(Scope='REGIONAL')
        rule_groups = rule_groups_response.get('RuleGroups', [])
        
        if not rule_groups:
            logger.info(f"No regional WAF rule groups found in region {region}")
            return findings
        
        for rule_group_summary in rule_groups:
            rule_group_name = rule_group_summary.get('Name', '')
            rule_group_id = rule_group_summary.get('Id', '')
            rule_group_arn = rule_group_summary.get('ARN', '')
            
            try:
                # Get detailed rule group information
                rule_group_response = wafv2_client.get_rule_group(
                    Name=rule_group_name,
                    Id=rule_group_id,
                    Scope='REGIONAL'
                )
                
                rule_group_details = rule_group_response.get('RuleGroup', {})
                rules = rule_group_details.get('Rules', [])
                
                # Check if rule group has rules
                has_rules = len(rules) > 0
                rule_count = len(rules)
                
                # Analyze rule types
                rule_types = []
                for rule in rules:
                    statement = rule.get('Statement', {})
                    if 'ManagedRuleGroupStatement' in statement:
                        rule_types.append('ManagedRuleGroup')
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
                
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'WAFv2RuleGroup',
                    'resource_id': rule_group_arn or rule_group_id,
                    'status': 'COMPLIANT' if has_rules else 'NON_COMPLIANT',
                    'compliance_status': 'PASS' if has_rules else 'FAIL',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Configure WAF regional rule groups with appropriate rules'),
                    'details': {
                        'rule_group_name': rule_group_name,
                        'rule_group_id': rule_group_id,
                        'rule_group_arn': rule_group_arn,
                        'has_rules': has_rules,
                        'rule_count': rule_count,
                        'rule_types': list(set(rule_types)),
                        'scope': 'REGIONAL',
                        'capacity': rule_group_details.get('Capacity', 0),
                        'description': rule_group_details.get('Description', ''),
                        'custom_response_bodies': rule_group_details.get('CustomResponseBodies', {})
                    }
                }
                
                findings.append(finding)
                
                if has_rules:
                    logger.info(f"WAF regional rule group {rule_group_name} contains {rule_count} rules")
                else:
                    logger.warning(f"WAF regional rule group {rule_group_name} is empty and provides no protection")
                    
            except Exception as rule_group_error:
                logger.error(f"Error checking rule group {rule_group_name}: {rule_group_error}")
                findings.append({
                    'region': region,
                    'profile': profile,
                    'resource_type': 'WAFv2RuleGroup',
                    'resource_id': rule_group_arn or rule_group_id,
                    'status': 'ERROR',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Configure WAF regional rule groups with appropriate rules'),
                    'error': str(rule_group_error)
                })
        
    except Exception as e:
        logger.error(f"Error in waf_regional_rulegroup_not_empty check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'WAFv2RuleGroup',
            'status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Configure WAF regional rule groups with appropriate rules'),
            'error': str(e)
        })
        
    return findings

def waf_regional_rulegroup_not_empty(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=waf_regional_rulegroup_not_empty_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = waf_regional_rulegroup_not_empty(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

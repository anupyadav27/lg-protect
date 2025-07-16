#!/usr/bin/env python3
"""
pci_4.0_aws - waf_global_webacl_with_rules

Checks whether a WAF Global Web ACL contains any WAF rules or rule groups
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
        'function_name': 'waf_global_webacl_with_rules',
        'id': 'WAF-005',
        'name': 'WAF Global Web ACL Rules Configuration',
        'description': 'Checks whether a WAF Global Web ACL contains any WAF rules or rule groups',
        'api_function': 'client=boto3.client("waf")',
        'user_function': 'get_web_acl()',
        'risk_level': 'HIGH',
        'recommendation': 'Ensure all WAF Global Web ACLs contain appropriate rules or rule groups'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('waf_global_webacl_with_rules')

def waf_global_webacl_with_rules_check(waf_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for waf_global_webacl_with_rules.
    
    Args:
        waf_client: Boto3 WAF client (auto-created by framework)
        region (str): AWS region (auto-managed by framework)
        profile (str): AWS profile name (auto-managed by framework)
        logger: Logger instance (auto-configured by framework)
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    try:
        # List all WAF Global Web ACLs
        response = waf_client.list_web_acls()
        web_acls = response.get('WebACLs', [])
        
        if not web_acls:
            logger.info(f"No WAF Global Web ACLs found in region {region}")
            return findings
        
        for web_acl_summary in web_acls:
            web_acl_id = web_acl_summary.get('WebACLId', 'Unknown')
            web_acl_name = web_acl_summary.get('Name', 'Unknown')
            
            try:
                # Get detailed Web ACL information
                web_acl_response = waf_client.get_web_acl(WebACLId=web_acl_id)
                web_acl_details = web_acl_response.get('WebACL', {})
                
                rules = web_acl_details.get('Rules', [])
                default_action = web_acl_details.get('DefaultAction', {})
                metric_name = web_acl_details.get('MetricName', 'Unknown')
                
                if rules and len(rules) > 0:
                    # Web ACL has rules - COMPLIANT
                    rule_types = []
                    rule_details = []
                    
                    for rule in rules:
                        rule_id = rule.get('RuleId', 'Unknown')
                        rule_type = rule.get('Type', 'Unknown')
                        action = rule.get('Action', {})
                        priority = rule.get('Priority', 0)
                        
                        rule_types.append(rule_type)
                        rule_details.append({
                            'rule_id': rule_id,
                            'type': rule_type,
                            'action': list(action.keys())[0] if action else 'Unknown',
                            'priority': priority
                        })
                    
                    finding = {
                        'region': region,
                        'profile': profile,
                        'resource_type': 'WAF_Global_WebACL',
                        'resource_id': f"{web_acl_name} ({web_acl_id})",
                        'status': 'COMPLIANT',
                        'compliance_status': 'PASS',
                        'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                        'recommendation': COMPLIANCE_DATA.get('recommendation', 'Maintain rule configuration'),
                        'details': {
                            'web_acl_name': web_acl_name,
                            'web_acl_id': web_acl_id,
                            'metric_name': metric_name,
                            'rules_count': len(rules),
                            'rule_types': rule_types,
                            'default_action': list(default_action.keys())[0] if default_action else 'Unknown',
                            'rules': rule_details
                        }
                    }
                else:
                    # Web ACL has no rules - NON_COMPLIANT
                    finding = {
                        'region': region,
                        'profile': profile,
                        'resource_type': 'WAF_Global_WebACL',
                        'resource_id': f"{web_acl_name} ({web_acl_id})",
                        'status': 'NON_COMPLIANT',
                        'compliance_status': 'FAIL',
                        'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                        'recommendation': 'Add rules or rule groups to this WAF Global Web ACL',
                        'details': {
                            'web_acl_name': web_acl_name,
                            'web_acl_id': web_acl_id,
                            'metric_name': metric_name,
                            'rules_count': 0,
                            'default_action': list(default_action.keys())[0] if default_action else 'Unknown',
                            'issue': 'Web ACL contains no rules or rule groups'
                        }
                    }
                
                findings.append(finding)
                
            except Exception as web_acl_error:
                logger.error(f"Error getting Web ACL details for {web_acl_id}: {web_acl_error}")
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'WAF_Global_WebACL',
                    'resource_id': f"{web_acl_name} ({web_acl_id})",
                    'status': 'ERROR',
                    'compliance_status': 'ERROR',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                    'recommendation': 'Review WAF Global Web ACL configuration',
                    'error': str(web_acl_error),
                    'details': {
                        'web_acl_name': web_acl_name,
                        'web_acl_id': web_acl_id
                    }
                }
                findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in waf_global_webacl_with_rules check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'WAF_Global_WebACL',
            'status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Review WAF Global configuration'),
            'error': str(e)
        })
        
    return findings

def waf_global_webacl_with_rules(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=waf_global_webacl_with_rules_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = waf_global_webacl_with_rules(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

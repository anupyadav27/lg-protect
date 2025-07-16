#!/usr/bin/env python3
"""
pci_4.0_aws - waf_regional_rule_with_conditions

Checks whether WAF regional rule contains conditions
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
        'function_name': 'waf_regional_rule_with_conditions',
        'id': 'WAF-004',
        'name': 'WAF Regional Rule Conditions',
        'description': 'Checks whether WAF regional rule contains conditions',
        'api_function': 'client=boto3.client("waf-regional")',
        'user_function': 'get_rule()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Ensure WAF regional rules contain appropriate conditions'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('waf_regional_rule_with_conditions')

def waf_regional_rule_with_conditions_check(waf_regional_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for waf_regional_rule_with_conditions.
    
    Args:
        waf_regional_client: Boto3 WAF Regional client (auto-created by framework)
        region (str): AWS region (auto-managed by framework)
        profile (str): AWS profile name (auto-managed by framework)
        logger: Logger instance (auto-configured by framework)
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    try:
        # List all WAF Regional rules
        response = waf_regional_client.list_rules()
        rules = response.get('Rules', [])
        
        if not rules:
            logger.info(f"No WAF Regional rules found in region {region}")
            return findings
        
        for rule_summary in rules:
            rule_id = rule_summary.get('RuleId', 'Unknown')
            rule_name = rule_summary.get('Name', 'Unknown')
            
            try:
                # Get detailed rule information
                rule_response = waf_regional_client.get_rule(RuleId=rule_id)
                rule_details = rule_response.get('Rule', {})
                
                predicates = rule_details.get('Predicates', [])
                metric_name = rule_details.get('MetricName', 'Unknown')
                
                if predicates and len(predicates) > 0:
                    # Rule has conditions - COMPLIANT
                    condition_types = []
                    condition_details = []
                    
                    for predicate in predicates:
                        predicate_type = predicate.get('Type', 'Unknown')
                        predicate_negated = predicate.get('Negated', False)
                        predicate_data_id = predicate.get('DataId', 'Unknown')
                        
                        condition_types.append(predicate_type)
                        condition_details.append({
                            'type': predicate_type,
                            'negated': predicate_negated,
                            'data_id': predicate_data_id
                        })
                    
                    finding = {
                        'region': region,
                        'profile': profile,
                        'resource_type': 'WAF_Regional_Rule',
                        'resource_id': f"{rule_name} ({rule_id})",
                        'status': 'COMPLIANT',
                        'compliance_status': 'PASS',
                        'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                        'recommendation': COMPLIANCE_DATA.get('recommendation', 'Maintain rule conditions'),
                        'details': {
                            'rule_name': rule_name,
                            'rule_id': rule_id,
                            'metric_name': metric_name,
                            'conditions_count': len(predicates),
                            'condition_types': condition_types,
                            'conditions': condition_details
                        }
                    }
                else:
                    # Rule has no conditions - NON_COMPLIANT
                    finding = {
                        'region': region,
                        'profile': profile,
                        'resource_type': 'WAF_Regional_Rule',
                        'resource_id': f"{rule_name} ({rule_id})",
                        'status': 'NON_COMPLIANT',
                        'compliance_status': 'FAIL',
                        'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                        'recommendation': 'Add conditions to this WAF Regional rule',
                        'details': {
                            'rule_name': rule_name,
                            'rule_id': rule_id,
                            'metric_name': metric_name,
                            'conditions_count': 0,
                            'issue': 'Rule contains no conditions/predicates'
                        }
                    }
                
                findings.append(finding)
                
            except Exception as rule_error:
                logger.error(f"Error getting rule details for {rule_id}: {rule_error}")
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'WAF_Regional_Rule',
                    'resource_id': f"{rule_name} ({rule_id})",
                    'status': 'ERROR',
                    'compliance_status': 'ERROR',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                    'recommendation': 'Review WAF Regional rule configuration',
                    'error': str(rule_error),
                    'details': {
                        'rule_name': rule_name,
                        'rule_id': rule_id
                    }
                }
                findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in waf_regional_rule_with_conditions check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'WAF_Regional_Rule',
            'status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Review WAF Regional configuration'),
            'error': str(e)
        })
        
    return findings

def waf_regional_rule_with_conditions(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=waf_regional_rule_with_conditions_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = waf_regional_rule_with_conditions(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

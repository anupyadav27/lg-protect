#!/usr/bin/env python3
"""
iso27001_2022_aws - ssmincidents_enabled_with_plans

Procedures for information security incident management should be established, implemented, maintained and continually improved.
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
        'compliance_name': 'iso27001_2022_aws',
        'function_name': 'ssmincidents_enabled_with_plans',
        'id': 'SSMI-001',
        'name': 'SSM Incidents Response Plans Configuration',
        'description': 'Procedures for information security incident management should be established, implemented, maintained and continually improved.',
        'api_function': 'client=boto3.client("ssm-incidents")',
        'user_function': 'list_response_plans()',
        'risk_level': 'HIGH',
        'recommendation': 'Configure SSM Incidents with appropriate response plans for incident management'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('ssmincidents_enabled_with_plans')

def ssmincidents_enabled_with_plans_check(ssm_incidents_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for ssmincidents_enabled_with_plans.
    
    Args:
        ssm_incidents_client: Boto3 SSM Incidents client (auto-created by framework)
        region (str): AWS region (auto-managed by framework)
        profile (str): AWS profile name (auto-managed by framework)
        logger: Logger instance (auto-configured by framework)
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    try:
        # List all response plans
        response = ssm_incidents_client.list_response_plans()
        response_plans = response.get('responsePlanSummaries', [])
        
        if not response_plans:
            # No response plans configured - NON_COMPLIANT
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'SSM_Incidents_ResponsePlan',
                'resource_id': 'No response plans configured',
                'status': 'NON_COMPLIANT',
                'compliance_status': 'FAIL',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                'recommendation': 'Configure at least one incident response plan in SSM Incidents',
                'details': {
                    'response_plans_count': 0,
                    'issue': 'No incident response plans configured'
                }
            }
            findings.append(finding)
        else:
            # Response plans exist - check their configuration
            for plan_summary in response_plans:
                plan_arn = plan_summary.get('arn', 'Unknown')
                plan_name = plan_summary.get('name', 'Unknown')
                
                try:
                    # Get detailed response plan information
                    plan_response = ssm_incidents_client.get_response_plan(arn=plan_arn)
                    plan_details = plan_response.get('responseplan', {})
                    
                    # Check if the plan has required components
                    actions = plan_details.get('actions', {})
                    chat_channel = plan_details.get('chatChannel', {})
                    engagements = plan_details.get('engagements', [])
                    incident_template = plan_details.get('incidentTemplate', {})
                    
                    # Check for proper configuration
                    has_actions = bool(actions.get('ssmAutomation') or actions.get('ssmReplication'))
                    has_chat_channel = bool(chat_channel)
                    has_engagements = len(engagements) > 0
                    has_incident_template = bool(incident_template.get('title'))
                    
                    # Plan is compliant if it has at least incident template and one other component
                    is_compliant = has_incident_template and (has_actions or has_chat_channel or has_engagements)
                    
                    if is_compliant:
                        # Well configured response plan - COMPLIANT
                        finding = {
                            'region': region,
                            'profile': profile,
                            'resource_type': 'SSM_Incidents_ResponsePlan',
                            'resource_id': f"{plan_name} ({plan_arn})",
                            'status': 'COMPLIANT',
                            'compliance_status': 'PASS',
                            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Maintain response plan configuration'),
                            'details': {
                                'plan_name': plan_name,
                                'plan_arn': plan_arn,
                                'has_actions': has_actions,
                                'has_chat_channel': has_chat_channel,
                                'has_engagements': has_engagements,
                                'has_incident_template': has_incident_template,
                                'engagements_count': len(engagements),
                                'incident_title': incident_template.get('title', 'Unknown')
                            }
                        }
                    else:
                        # Poorly configured response plan - NON_COMPLIANT
                        issues = []
                        if not has_incident_template:
                            issues.append('Missing incident template')
                        if not (has_actions or has_chat_channel or has_engagements):
                            issues.append('No actions, chat channels, or engagements configured')
                        
                        finding = {
                            'region': region,
                            'profile': profile,
                            'resource_type': 'SSM_Incidents_ResponsePlan',
                            'resource_id': f"{plan_name} ({plan_arn})",
                            'status': 'NON_COMPLIANT',
                            'compliance_status': 'FAIL',
                            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                            'recommendation': 'Configure incident template and response actions for this plan',
                            'details': {
                                'plan_name': plan_name,
                                'plan_arn': plan_arn,
                                'has_actions': has_actions,
                                'has_chat_channel': has_chat_channel,
                                'has_engagements': has_engagements,
                                'has_incident_template': has_incident_template,
                                'engagements_count': len(engagements),
                                'issues': issues
                            }
                        }
                    
                    findings.append(finding)
                    
                except Exception as plan_error:
                    logger.error(f"Error getting response plan details for {plan_arn}: {plan_error}")
                    finding = {
                        'region': region,
                        'profile': profile,
                        'resource_type': 'SSM_Incidents_ResponsePlan',
                        'resource_id': f"{plan_name} ({plan_arn})",
                        'status': 'ERROR',
                        'compliance_status': 'ERROR',
                        'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                        'recommendation': 'Review response plan configuration',
                        'error': str(plan_error),
                        'details': {
                            'plan_name': plan_name,
                            'plan_arn': plan_arn
                        }
                    }
                    findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in ssmincidents_enabled_with_plans check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'SSM_Incidents_ResponsePlan',
            'status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Review SSM Incidents configuration'),
            'error': str(e)
        })
        
    return findings

def ssmincidents_enabled_with_plans(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=ssmincidents_enabled_with_plans_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = ssmincidents_enabled_with_plans(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

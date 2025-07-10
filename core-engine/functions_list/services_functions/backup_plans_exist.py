#!/usr/bin/env python3
"""
iso27001_2022_aws - backup_plans_exist

Backup copies of information, software and systems should be maintained and regularly tested in accordance with the agreed topic-specific policy on backup.
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
                    'recommendation': entry.get('Recommendation', 'Create and configure AWS Backup plans')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'iso27001_2022_aws',
        'function_name': 'backup_plans_exist',
        'id': 'ISO27001-2022-AWS-BACKUP-PLANS',
        'name': 'AWS Backup Plans Exist',
        'description': 'Backup copies of information, software and systems should be maintained and regularly tested in accordance with the agreed topic-specific policy on backup.',
        'api_function': 'client = boto3.client(\'backup\')',
        'user_function': 'list_backup_plans()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Create and configure AWS Backup plans'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('backup_plans_exist')

def backup_plans_exist_check(backup_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Check if AWS Backup plans exist.
    
    Args:
        backup_client: Boto3 Backup client
        region (str): AWS region
        profile (str): AWS profile name
        logger: Logger instance
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    try:
        # List all backup plans
        response = backup_client.list_backup_plans()
        backup_plans = response.get('BackupPlansList', [])
        
        if not backup_plans:
            # No backup plans found - non-compliant
            findings.append({
                'region': region,
                'profile': profile,
                'resource_type': 'AWS Backup',
                'resource_id': f'backup-plans-{region}',
                'status': 'NON_COMPLIANT',
                'compliance_status': 'FAIL',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                'recommendation': COMPLIANCE_DATA.get('recommendation', 'Create and configure AWS Backup plans'),
                'details': {
                    'backup_plan_count': 0,
                    'issue': 'No AWS Backup plans found in this region'
                }
            })
        else:
            # Analyze each backup plan for completeness
            active_plans = 0
            
            for plan in backup_plans:
                plan_id = plan.get('BackupPlanId', 'Unknown')
                plan_name = plan.get('BackupPlanName', 'Unknown')
                plan_arn = plan.get('BackupPlanArn', '')
                creation_date = plan.get('CreationDate')
                
                try:
                    # Get detailed plan information
                    plan_details = backup_client.get_backup_plan(BackupPlanId=plan_id)
                    backup_plan = plan_details.get('BackupPlan', {})
                    
                    # Check if plan has rules
                    rules = backup_plan.get('Rules', [])
                    
                    if rules:
                        active_plans += 1
                        
                        # Check for backup selections (what resources are backed up)
                        try:
                            selections_response = backup_client.list_backup_selections(BackupPlanId=plan_id)
                            selections = selections_response.get('BackupSelectionsList', [])
                            
                            if selections:
                                # Plan has rules and selections - compliant
                                findings.append({
                                    'region': region,
                                    'profile': profile,
                                    'resource_type': 'AWS Backup Plan',
                                    'resource_id': plan_name,
                                    'status': 'COMPLIANT',
                                    'compliance_status': 'PASS',
                                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                                    'recommendation': 'Backup plan is properly configured',
                                    'details': {
                                        'plan_id': plan_id,
                                        'plan_name': plan_name,
                                        'plan_arn': plan_arn,
                                        'creation_date': creation_date.isoformat() if creation_date else 'Unknown',
                                        'rule_count': len(rules),
                                        'selection_count': len(selections),
                                        'rules': [
                                            {
                                                'rule_name': rule.get('RuleName', 'Unknown'),
                                                'target_backup_vault': rule.get('TargetBackupVault', 'Unknown'),
                                                'schedule_expression': rule.get('ScheduleExpression', 'Unknown')
                                            }
                                            for rule in rules[:3]  # Limit to first 3 rules
                                        ]
                                    }
                                })
                            else:
                                # Plan has rules but no selections - partially compliant
                                findings.append({
                                    'region': region,
                                    'profile': profile,
                                    'resource_type': 'AWS Backup Plan',
                                    'resource_id': plan_name,
                                    'status': 'NON_COMPLIANT',
                                    'compliance_status': 'FAIL',
                                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                                    'recommendation': 'Add backup selections to specify which resources to backup',
                                    'details': {
                                        'plan_id': plan_id,
                                        'plan_name': plan_name,
                                        'plan_arn': plan_arn,
                                        'creation_date': creation_date.isoformat() if creation_date else 'Unknown',
                                        'rule_count': len(rules),
                                        'selection_count': 0,
                                        'issue': 'Backup plan has no backup selections configured'
                                    }
                                })
                        except Exception as e:
                            logger.warning(f"Error checking backup selections for plan {plan_name}: {e}")
                            findings.append({
                                'region': region,
                                'profile': profile,
                                'resource_type': 'AWS Backup Plan',
                                'resource_id': plan_name,
                                'status': 'ERROR',
                                'compliance_status': 'ERROR',
                                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                                'recommendation': COMPLIANCE_DATA.get('recommendation', 'Create and configure AWS Backup plans'),
                                'details': {
                                    'plan_id': plan_id,
                                    'plan_name': plan_name,
                                    'error': f'Error checking backup selections: {str(e)}'
                                }
                            })
                    else:
                        # Plan has no rules - non-compliant
                        findings.append({
                            'region': region,
                            'profile': profile,
                            'resource_type': 'AWS Backup Plan',
                            'resource_id': plan_name,
                            'status': 'NON_COMPLIANT',
                            'compliance_status': 'FAIL',
                            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                            'recommendation': 'Add backup rules to the backup plan',
                            'details': {
                                'plan_id': plan_id,
                                'plan_name': plan_name,
                                'plan_arn': plan_arn,
                                'creation_date': creation_date.isoformat() if creation_date else 'Unknown',
                                'rule_count': 0,
                                'issue': 'Backup plan has no backup rules configured'
                            }
                        })
                        
                except Exception as e:
                    logger.warning(f"Error getting details for backup plan {plan_name}: {e}")
                    findings.append({
                        'region': region,
                        'profile': profile,
                        'resource_type': 'AWS Backup Plan',
                        'resource_id': plan_name,
                        'status': 'ERROR',
                        'compliance_status': 'ERROR',
                        'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                        'recommendation': COMPLIANCE_DATA.get('recommendation', 'Create and configure AWS Backup plans'),
                        'details': {
                            'plan_id': plan_id,
                            'plan_name': plan_name,
                            'error': f'Error getting plan details: {str(e)}'
                        }
                    })
            
            # Add summary finding
            if active_plans == 0:
                findings.append({
                    'region': region,
                    'profile': profile,
                    'resource_type': 'AWS Backup Summary',
                    'resource_id': f'backup-summary-{region}',
                    'status': 'NON_COMPLIANT',
                    'compliance_status': 'FAIL',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Create and configure AWS Backup plans'),
                    'details': {
                        'total_backup_plans': len(backup_plans),
                        'active_backup_plans': active_plans,
                        'issue': 'No active backup plans with proper configuration found'
                    }
                })
        
    except Exception as e:
        logger.error(f"Error in backup_plans_exist check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'AWS Backup',
            'resource_id': f'backup-check-{region}',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Create and configure AWS Backup plans'),
            'error': str(e)
        })
        
    return findings

def backup_plans_exist(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=backup_plans_exist_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = backup_plans_exist(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

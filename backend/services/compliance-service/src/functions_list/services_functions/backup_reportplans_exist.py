#!/usr/bin/env python3
"""
iso27001_2022_aws - backup_reportplans_exist

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
                    'recommendation': entry.get('Recommendation', 'Create and configure AWS Backup report plans')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'iso27001_2022_aws',
        'function_name': 'backup_reportplans_exist',
        'id': 'ISO27001-2022-AWS-BACKUP-REPORTS',
        'name': 'AWS Backup Report Plans Exist',
        'description': 'Backup copies of information, software and systems should be maintained and regularly tested in accordance with the agreed topic-specific policy on backup.',
        'api_function': 'client = boto3.client(\'backup\')',
        'user_function': 'list_report_plans()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Create and configure AWS Backup report plans'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('backup_reportplans_exist')

def backup_reportplans_exist_check(backup_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Check if AWS Backup report plans exist.
    
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
        # List all backup report plans
        response = backup_client.list_report_plans()
        report_plans = response.get('ReportPlans', [])
        
        if not report_plans:
            # No report plans found - non-compliant
            findings.append({
                'region': region,
                'profile': profile,
                'resource_type': 'AWS Backup Report Plans',
                'resource_id': f'backup-report-plans-{region}',
                'status': 'NON_COMPLIANT',
                'compliance_status': 'FAIL',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                'recommendation': COMPLIANCE_DATA.get('recommendation', 'Create and configure AWS Backup report plans'),
                'details': {
                    'report_plan_count': 0,
                    'issue': 'No AWS Backup report plans found in this region'
                }
            })
        else:
            # Analyze each report plan
            for plan in report_plans:
                plan_name = plan.get('ReportPlanName', 'Unknown')
                plan_arn = plan.get('ReportPlanArn', '')
                creation_time = plan.get('CreationTime')
                deployment_status = plan.get('DeploymentStatus', 'Unknown')
                
                try:
                    # Get detailed report plan information
                    plan_details = backup_client.describe_report_plan(ReportPlanName=plan_name)
                    report_plan = plan_details.get('ReportPlan', {})
                    
                    # Check report delivery channel
                    report_delivery_channel = report_plan.get('ReportDeliveryChannel', {})
                    s3_bucket_name = report_delivery_channel.get('S3BucketName')
                    
                    # Check report setting
                    report_setting = report_plan.get('ReportSetting', {})
                    report_template = report_setting.get('ReportTemplate')
                    
                    if deployment_status == 'COMPLETED' and s3_bucket_name and report_template:
                        # Report plan is properly configured - compliant
                        findings.append({
                            'region': region,
                            'profile': profile,
                            'resource_type': 'AWS Backup Report Plan',
                            'resource_id': plan_name,
                            'status': 'COMPLIANT',
                            'compliance_status': 'PASS',
                            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                            'recommendation': 'Backup report plan is properly configured',
                            'details': {
                                'plan_name': plan_name,
                                'plan_arn': plan_arn,
                                'creation_time': creation_time.isoformat() if creation_time else 'Unknown',
                                'deployment_status': deployment_status,
                                's3_bucket_name': s3_bucket_name,
                                'report_template': report_template
                            }
                        })
                    else:
                        # Report plan has configuration issues - non-compliant
                        issues = []
                        if deployment_status != 'COMPLETED':
                            issues.append(f'Deployment status is {deployment_status}')
                        if not s3_bucket_name:
                            issues.append('No S3 bucket configured for report delivery')
                        if not report_template:
                            issues.append('No report template configured')
                        
                        findings.append({
                            'region': region,
                            'profile': profile,
                            'resource_type': 'AWS Backup Report Plan',
                            'resource_id': plan_name,
                            'status': 'NON_COMPLIANT',
                            'compliance_status': 'FAIL',
                            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                            'recommendation': 'Fix report plan configuration issues',
                            'details': {
                                'plan_name': plan_name,
                                'plan_arn': plan_arn,
                                'creation_time': creation_time.isoformat() if creation_time else 'Unknown',
                                'deployment_status': deployment_status,
                                's3_bucket_name': s3_bucket_name or 'Not configured',
                                'report_template': report_template or 'Not configured',
                                'issues': issues
                            }
                        })
                        
                except Exception as e:
                    logger.warning(f"Error getting details for report plan {plan_name}: {e}")
                    findings.append({
                        'region': region,
                        'profile': profile,
                        'resource_type': 'AWS Backup Report Plan',
                        'resource_id': plan_name,
                        'status': 'ERROR',
                        'compliance_status': 'ERROR',
                        'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                        'recommendation': COMPLIANCE_DATA.get('recommendation', 'Create and configure AWS Backup report plans'),
                        'details': {
                            'plan_name': plan_name,
                            'plan_arn': plan_arn,
                            'error': f'Error getting plan details: {str(e)}'
                        }
                    })
            
            # Add summary finding
            compliant_plans = sum(1 for finding in findings if finding.get('status') == 'COMPLIANT')
            
            findings.append({
                'region': region,
                'profile': profile,
                'resource_type': 'AWS Backup Report Summary',
                'resource_id': f'backup-report-summary-{region}',
                'status': 'COMPLIANT' if compliant_plans > 0 else 'NON_COMPLIANT',
                'compliance_status': 'PASS' if compliant_plans > 0 else 'FAIL',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                'recommendation': 'Continue monitoring backup report plans' if compliant_plans > 0 else COMPLIANCE_DATA.get('recommendation', 'Create and configure AWS Backup report plans'),
                'details': {
                    'total_report_plans': len(report_plans),
                    'compliant_report_plans': compliant_plans,
                    'compliance_percentage': round((compliant_plans / len(report_plans)) * 100, 2) if report_plans else 0
                }
            })
        
    except Exception as e:
        logger.error(f"Error in backup_reportplans_exist check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'AWS Backup Report Plans',
            'resource_id': f'backup-report-check-{region}',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Create and configure AWS Backup report plans'),
            'error': str(e)
        })
        
    return findings

def backup_reportplans_exist(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=backup_reportplans_exist_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = backup_reportplans_exist(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

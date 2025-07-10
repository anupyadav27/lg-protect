#!/usr/bin/env python3
"""
iso27001_2022_aws - codebuild_report_group_export_encrypted

Read and write access to source code, development tools and software libraries should be appropriately managed.
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
        'function_name': 'codebuild_report_group_export_encrypted',
        'id': 'ISO-27001-2022-A.8.2',
        'name': 'Source Code Access Management',
        'description': 'Read and write access to source code, development tools and software libraries should be appropriately managed.',
        'api_function': 'client = boto3.client(\'codebuild\')',
        'user_function': 'list_report_groups(), batch_get_report_groups()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Ensure CodeBuild report group exports are encrypted to protect sensitive build data'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('codebuild_report_group_export_encrypted')

def codebuild_report_group_export_encrypted_check(codebuild_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for codebuild_report_group_export_encrypted.
    
    Args:
        codebuild_client: Boto3 CodeBuild client (auto-created by framework)
        region (str): AWS region (auto-managed by framework)
        profile (str): AWS profile name (auto-managed by framework)
        logger: Logger instance (auto-configured by framework)
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    try:
        # Get all CodeBuild report groups
        response = codebuild_client.list_report_groups()
        report_group_arns = response.get('reportGroups', [])
        
        if not report_group_arns:
            # No CodeBuild report groups found
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'CodeBuild',
                'resource_id': f'no-report-groups-{region}',
                'status': 'COMPLIANT',
                'compliance_status': 'PASS',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                'recommendation': 'No CodeBuild report groups found in this region',
                'details': {
                    'report_groups_count': 0,
                    'message': 'No CodeBuild report groups found to check for export encryption'
                }
            }
            findings.append(finding)
            return findings
        
        # Get detailed report group information in batches
        batch_size = 100  # AWS API limit
        for i in range(0, len(report_group_arns), batch_size):
            batch = report_group_arns[i:i + batch_size]
            
            try:
                report_groups_response = codebuild_client.batch_get_report_groups(reportGroupArns=batch)
                report_groups = report_groups_response.get('reportGroups', [])
                
                for report_group in report_groups:
                    report_group_name = report_group.get('name', 'unknown')
                    report_group_arn = report_group.get('arn', 'unknown')
                    
                    # Check export configuration
                    export_config = report_group.get('exportConfig', {})
                    export_config_type = export_config.get('exportConfigType', 'NO_EXPORT')
                    
                    # Check S3 export encryption if configured
                    s3_destination = export_config.get('s3Destination', {})
                    encryption_disabled = s3_destination.get('encryptionDisabled', True)
                    encryption_key = s3_destination.get('encryptionKey', '')
                    
                    # Determine compliance status
                    if export_config_type == 'NO_EXPORT':
                        # No export configured - compliant but not ideal
                        status = 'COMPLIANT'
                        compliance_status = 'PASS'
                        risk_level = 'LOW'
                        recommendation = 'No export configured. Consider enabling encrypted exports for audit purposes.'
                    elif export_config_type == 'S3':
                        if not encryption_disabled:
                            # S3 export with encryption enabled
                            status = 'COMPLIANT'
                            compliance_status = 'PASS'
                            risk_level = 'LOW'
                            recommendation = 'S3 export is properly encrypted'
                        else:
                            # S3 export without encryption
                            status = 'NON_COMPLIANT'
                            compliance_status = 'FAIL'
                            risk_level = COMPLIANCE_DATA.get('risk_level', 'MEDIUM')
                            recommendation = COMPLIANCE_DATA.get('recommendation', 'Enable encryption for CodeBuild report group S3 exports')
                    else:
                        # Unknown export type
                        status = 'NON_COMPLIANT'
                        compliance_status = 'FAIL'
                        risk_level = COMPLIANCE_DATA.get('risk_level', 'MEDIUM')
                        recommendation = 'Unknown export configuration type. Review and configure proper encryption.'
                    
                    finding = {
                        'region': region,
                        'profile': profile,
                        'resource_type': 'CodeBuild',
                        'resource_id': report_group_name,
                        'status': status,
                        'compliance_status': compliance_status,
                        'risk_level': risk_level,
                        'recommendation': recommendation,
                        'details': {
                            'report_group_name': report_group_name,
                            'report_group_arn': report_group_arn,
                            'export_config_type': export_config_type,
                            'encryption_disabled': encryption_disabled,
                            'encryption_key': encryption_key,
                            's3_destination': s3_destination,
                            'export_config': export_config
                        }
                    }
                    
                    findings.append(finding)
                    
            except Exception as batch_error:
                logger.warning(f"Error getting report group details for batch: {batch_error}")
                # Create error finding for this batch
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'CodeBuild',
                    'resource_id': f'batch-error-{i}',
                    'status': 'ERROR',
                    'compliance_status': 'ERROR',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                    'recommendation': 'Unable to check export encryption for some report groups',
                    'details': {
                        'batch_report_groups': batch,
                        'error': str(batch_error)
                    }
                }
                findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in codebuild_report_group_export_encrypted check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'CodeBuild',
            'resource_id': f'error-check-{region}',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Ensure CodeBuild report group exports are encrypted'),
            'error': str(e)
        })
        
    return findings

def codebuild_report_group_export_encrypted(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=codebuild_report_group_export_encrypted_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = codebuild_report_group_export_encrypted(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

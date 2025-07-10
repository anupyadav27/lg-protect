#!/usr/bin/env python3
"""
iso27001_2022_aws - wellarchitected_workload_no_high_or_medium_risks

Information security policy and topic-specific policies should be defined, approved by management, published, communicated to and acknowledged by relevant personnel and relevant interested parties, and reviewed at planned intervals and if significant changes occur.
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
        'function_name': 'wellarchitected_workload_no_high_or_medium_risks',
        'id': 'WA-001',
        'name': 'Well-Architected Workload Risk Assessment',
        'description': 'Information security policy and topic-specific policies should be defined, approved by management, published, communicated to and acknowledged by relevant personnel and relevant interested parties, and reviewed at planned intervals and if significant changes occur.',
        'api_function': 'client=boto3.client("wellarchitected")',
        'user_function': 'list_workloads(), list_answers()',
        'risk_level': 'HIGH',
        'recommendation': 'Review and remediate high and medium risk findings in Well-Architected workloads'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('wellarchitected_workload_no_high_or_medium_risks')

def wellarchitected_workload_no_high_or_medium_risks_check(wellarchitected_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for wellarchitected_workload_no_high_or_medium_risks.
    
    Args:
        wellarchitected_client: Boto3 Well-Architected client (auto-created by framework)
        region (str): AWS region (auto-managed by framework)
        profile (str): AWS profile name (auto-managed by framework)
        logger: Logger instance (auto-configured by framework)
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    try:
        # List all Well-Architected workloads
        response = wellarchitected_client.list_workloads()
        workloads = response.get('WorkloadSummaries', [])
        
        if not workloads:
            logger.info(f"No Well-Architected workloads found in region {region}")
            return findings
        
        for workload in workloads:
            workload_id = workload.get('WorkloadId', 'Unknown')
            workload_name = workload.get('WorkloadName', 'Unknown')
            workload_arn = workload.get('WorkloadArn', 'Unknown')
            
            try:
                # Get detailed workload information
                workload_response = wellarchitected_client.get_workload(WorkloadId=workload_id)
                workload_details = workload_response.get('Workload', {})
                
                improvement_status = workload_details.get('ImprovementStatus', 'Unknown')
                risk_counts = workload_details.get('RiskCounts', {})
                
                # Count high and medium risks
                high_risks = risk_counts.get('HIGH', 0)
                medium_risks = risk_counts.get('MEDIUM', 0)
                low_risks = risk_counts.get('LOW', 0)
                not_applicable = risk_counts.get('NOT_APPLICABLE', 0)
                unanswered = risk_counts.get('UNANSWERED', 0)
                
                total_high_medium = high_risks + medium_risks
                
                if total_high_medium == 0:
                    # No high or medium risks - COMPLIANT
                    finding = {
                        'region': region,
                        'profile': profile,
                        'resource_type': 'WellArchitected_Workload',
                        'resource_id': f"{workload_name} ({workload_id})",
                        'status': 'COMPLIANT',
                        'compliance_status': 'PASS',
                        'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                        'recommendation': COMPLIANCE_DATA.get('recommendation', 'Maintain workload best practices'),
                        'details': {
                            'workload_name': workload_name,
                            'workload_id': workload_id,
                            'improvement_status': improvement_status,
                            'high_risks': high_risks,
                            'medium_risks': medium_risks,
                            'low_risks': low_risks,
                            'not_applicable': not_applicable,
                            'unanswered': unanswered,
                            'total_high_medium_risks': total_high_medium
                        }
                    }
                else:
                    # Has high or medium risks - NON_COMPLIANT
                    finding = {
                        'region': region,
                        'profile': profile,
                        'resource_type': 'WellArchitected_Workload',
                        'resource_id': f"{workload_name} ({workload_id})",
                        'status': 'NON_COMPLIANT',
                        'compliance_status': 'FAIL',
                        'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                        'recommendation': 'Address high and medium risk findings in this workload',
                        'details': {
                            'workload_name': workload_name,
                            'workload_id': workload_id,
                            'improvement_status': improvement_status,
                            'high_risks': high_risks,
                            'medium_risks': medium_risks,
                            'low_risks': low_risks,
                            'not_applicable': not_applicable,
                            'unanswered': unanswered,
                            'total_high_medium_risks': total_high_medium,
                            'issue': f'Workload has {high_risks} high risk(s) and {medium_risks} medium risk(s)'
                        }
                    }
                
                # Try to get additional lens information if available
                try:
                    lenses_response = wellarchitected_client.list_lens_reviews(WorkloadId=workload_id)
                    lens_reviews = lenses_response.get('LensReviewSummaries', [])
                    
                    lens_info = []
                    for lens in lens_reviews:
                        lens_alias = lens.get('LensAlias', 'Unknown')
                        lens_status = lens.get('LensStatus', 'Unknown')
                        lens_risk_counts = lens.get('RiskCounts', {})
                        
                        lens_info.append({
                            'lens_alias': lens_alias,
                            'lens_status': lens_status,
                            'risk_counts': lens_risk_counts
                        })
                    
                    finding['details']['lenses'] = lens_info
                    
                except Exception as lens_error:
                    logger.warning(f"Could not retrieve lens information for workload {workload_id}: {lens_error}")
                
                findings.append(finding)
                
            except Exception as workload_error:
                logger.error(f"Error getting workload details for {workload_id}: {workload_error}")
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'WellArchitected_Workload',
                    'resource_id': f"{workload_name} ({workload_id})",
                    'status': 'ERROR',
                    'compliance_status': 'ERROR',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                    'recommendation': 'Review Well-Architected workload configuration',
                    'error': str(workload_error),
                    'details': {
                        'workload_name': workload_name,
                        'workload_id': workload_id
                    }
                }
                findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in wellarchitected_workload_no_high_or_medium_risks check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'WellArchitected_Workload',
            'status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Review Well-Architected configuration'),
            'error': str(e)
        })
        
    return findings

def wellarchitected_workload_no_high_or_medium_risks(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=wellarchitected_workload_no_high_or_medium_risks_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = wellarchitected_workload_no_high_or_medium_risks(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

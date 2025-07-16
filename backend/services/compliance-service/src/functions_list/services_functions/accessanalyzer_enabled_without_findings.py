#!/usr/bin/env python3
"""
iso27001_2022_aws - accessanalyzer_enabled_without_findings

Access to information and other associated assets should be restricted in accordance with the established topic-specific policy on access control.
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
                    'recommendation': entry.get('Recommendation', 'Enable IAM Access Analyzer and resolve all findings')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'iso27001_2022_aws',
        'function_name': 'accessanalyzer_enabled_without_findings',
        'id': 'A.9.1.1',
        'name': 'Access control policy',
        'description': 'Access to information and other associated assets should be restricted in accordance with the established topic-specific policy on access control.',
        'api_function': 'client=boto3.client(\'accessanalyzer\')',
        'user_function': 'list_findings()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Enable IAM Access Analyzer and resolve all findings'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('accessanalyzer_enabled_without_findings')

def accessanalyzer_enabled_without_findings_check(accessanalyzer_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for accessanalyzer_enabled_without_findings.
    
    Args:
        accessanalyzer_client: Boto3 Access Analyzer client (auto-created by framework)
        region (str): AWS region (auto-managed by framework)
        profile (str): AWS profile name (auto-managed by framework)
        logger: Logger instance (auto-configured by framework)
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    try:
        # First, list all analyzers
        analyzers_response = accessanalyzer_client.list_analyzers()
        analyzers = analyzers_response.get('analyzers', [])
        
        # Check if at least one analyzer is active
        active_analyzers = [analyzer for analyzer in analyzers if analyzer.get('status') == 'ACTIVE']
        
        if not active_analyzers:
            # No active analyzers found
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'IAM Access Analyzer',
                'resource_id': f'access-analyzer-{region}',
                'status': 'NON_COMPLIANT',
                'compliance_status': 'FAIL',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable IAM Access Analyzer and resolve all findings'),
                'details': {
                    'issue': 'No active Access Analyzer found',
                    'active_analyzers_count': 0,
                    'total_analyzers_count': len(analyzers)
                }
            }
            findings.append(finding)
            return findings
        
        # Check findings for each active analyzer
        for analyzer in active_analyzers:
            analyzer_arn = analyzer.get('arn')
            analyzer_name = analyzer.get('name')
            
            try:
                # List findings for this analyzer
                findings_response = accessanalyzer_client.list_findings(analyzerArn=analyzer_arn)
                analyzer_findings = findings_response.get('findings', [])
                
                # Filter active findings
                active_findings = [f for f in analyzer_findings if f.get('status') == 'ACTIVE']
                
                if active_findings:
                    status = 'NON_COMPLIANT'
                    compliance_status = 'FAIL'
                    finding_details = []
                    
                    for finding_item in active_findings[:10]:  # Limit to first 10 findings for brevity
                        finding_details.append({
                            'finding_id': finding_item.get('id'),
                            'resource_type': finding_item.get('resourceType'),
                            'resource': finding_item.get('resource'),
                            'condition': finding_item.get('condition'),
                            'action': finding_item.get('action'),
                            'principal': finding_item.get('principal'),
                            'created_at': finding_item.get('createdAt').isoformat() if finding_item.get('createdAt') else None
                        })
                else:
                    status = 'COMPLIANT'
                    compliance_status = 'PASS'
                    finding_details = []
                
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'IAM Access Analyzer',
                    'resource_id': analyzer_arn,
                    'status': status,
                    'compliance_status': compliance_status,
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable IAM Access Analyzer and resolve all findings'),
                    'details': {
                        'analyzer_name': analyzer_name,
                        'analyzer_arn': analyzer_arn,
                        'active_findings_count': len(active_findings),
                        'total_findings_count': len(analyzer_findings),
                        'active_findings': finding_details
                    }
                }
                
                findings.append(finding)
                
            except Exception as e:
                logger.error(f"Error checking findings for analyzer {analyzer_name}: {e}")
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'IAM Access Analyzer',
                    'resource_id': analyzer_arn,
                    'status': 'ERROR',
                    'compliance_status': 'ERROR',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable IAM Access Analyzer and resolve all findings'),
                    'error': f"Error checking findings: {str(e)}"
                }
                findings.append(finding)
        
    except accessanalyzer_client.exceptions.AccessDeniedException as e:
        logger.error(f"Access denied for Access Analyzer in {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'IAM Access Analyzer',
            'resource_id': f'access-analyzer-{region}',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable IAM Access Analyzer and resolve all findings'),
            'error': f"Access denied: {str(e)}"
        })
    except Exception as e:
        logger.error(f"Error in accessanalyzer_enabled_without_findings check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'IAM Access Analyzer',
            'resource_id': f'access-analyzer-{region}',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable IAM Access Analyzer and resolve all findings'),
            'error': str(e)
        })
        
    return findings

def accessanalyzer_enabled_without_findings(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=accessanalyzer_enabled_without_findings_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = accessanalyzer_enabled_without_findings(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

#!/usr/bin/env python3
"""
cis_4.0_aws - accessanalyzer_enabled

Ensure that IAM Access Analyzer is enabled for all regions
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
                    'recommendation': entry.get('Recommendation', 'Enable IAM Access Analyzer for all regions')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'cis_4.0_aws',
        'function_name': 'accessanalyzer_enabled',
        'id': '1.21',
        'name': 'Ensure that IAM Access Analyzer is enabled for all regions',
        'description': 'Ensure that IAM Access Analyzer is enabled for all regions',
        'api_function': 'client = boto3.client(\'accessanalyzer\')',
        'user_function': 'list_analyzers()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Enable IAM Access Analyzer for all regions'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('accessanalyzer_enabled')

def accessanalyzer_enabled_check(accessanalyzer_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for accessanalyzer_enabled.
    
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
        # List all analyzers in the region
        response = accessanalyzer_client.list_analyzers()
        
        analyzers = response.get('analyzers', [])
        
        # Check if at least one analyzer is active
        active_analyzers = [analyzer for analyzer in analyzers if analyzer.get('status') == 'ACTIVE']
        
        if active_analyzers:
            status = 'COMPLIANT'
            compliance_status = 'PASS'
            analyzer_details = []
            
            for analyzer in active_analyzers:
                analyzer_details.append({
                    'analyzer_name': analyzer.get('name'),
                    'analyzer_arn': analyzer.get('arn'),
                    'type': analyzer.get('type'),
                    'status': analyzer.get('status'),
                    'created_at': analyzer.get('createdAt').isoformat() if analyzer.get('createdAt') else None
                })
        else:
            status = 'NON_COMPLIANT'
            compliance_status = 'FAIL'
            analyzer_details = []
        
        finding = {
            'region': region,
            'profile': profile,
            'resource_type': 'IAM Access Analyzer',
            'resource_id': f'access-analyzer-{region}',
            'status': status,
            'compliance_status': compliance_status,
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable IAM Access Analyzer for all regions'),
            'details': {
                'active_analyzers_count': len(active_analyzers),
                'total_analyzers_count': len(analyzers),
                'active_analyzers': analyzer_details
            }
        }
        
        findings.append(finding)
        
    except accessanalyzer_client.exceptions.ServiceQuotaExceededException as e:
        logger.error(f"Service quota exceeded for Access Analyzer in {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'IAM Access Analyzer',
            'resource_id': f'access-analyzer-{region}',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable IAM Access Analyzer for all regions'),
            'error': f"Service quota exceeded: {str(e)}"
        })
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
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable IAM Access Analyzer for all regions'),
            'error': f"Access denied: {str(e)}"
        })
    except Exception as e:
        logger.error(f"Error in accessanalyzer_enabled check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'IAM Access Analyzer',
            'resource_id': f'access-analyzer-{region}',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable IAM Access Analyzer for all regions'),
            'error': str(e)
        })
        
    return findings

def accessanalyzer_enabled(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=accessanalyzer_enabled_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = accessanalyzer_enabled(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

#!/usr/bin/env python3
"""
aws_foundational_security_best_practices_aws - macie_automated_sensitive_data_discovery_enabled

This control checks whether Amazon Macie has automated sensitive data discovery enabled to continuously monitor S3 buckets.
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
                    'risk_level': entry.get('Risk Level', 'HIGH'),
                    'recommendation': entry.get('Recommendation', 'Enable automated sensitive data discovery in Amazon Macie')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'aws_foundational_security_best_practices_aws',
        'function_name': 'macie_automated_sensitive_data_discovery_enabled',
        'id': 'Macie.2',
        'name': 'Amazon Macie should have automated sensitive data discovery enabled',
        'description': 'This control checks whether Amazon Macie has automated sensitive data discovery enabled to continuously monitor S3 buckets.',
        'api_function': 'client = boto3.client("macie2")',
        'user_function': 'get_automated_discovery_configuration()',
        'risk_level': 'HIGH',
        'recommendation': 'Enable automated sensitive data discovery in Amazon Macie'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('macie_automated_sensitive_data_discovery_enabled')

def macie_automated_sensitive_data_discovery_enabled_check(macie2_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for macie_automated_sensitive_data_discovery_enabled.
    
    Args:
        macie2_client: Boto3 Macie2 client (auto-created by framework)
        region (str): AWS region (auto-managed by framework)
        profile (str): AWS profile name (auto-managed by framework)
        logger: Logger instance (auto-configured by framework)
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    try:
        logger.info("Checking if Macie automated sensitive data discovery is enabled...")
        
        # First check if Macie is enabled
        try:
            macie_session = macie2_client.get_macie_session()
            macie_status = macie_session.get('status', 'UNKNOWN')
            
            if macie_status != 'ENABLED':
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'Macie Automated Discovery',
                    'resource_id': f"macie-auto-discovery-{region}",
                    'status': 'NON_COMPLIANT',
                    'compliance_status': 'FAIL',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable automated sensitive data discovery in Amazon Macie'),
                    'details': {
                        'macie_status': macie_status,
                        'automated_discovery_status': 'UNAVAILABLE',
                        'message': 'Amazon Macie is not enabled, automated discovery unavailable'
                    }
                }
                findings.append(finding)
                return findings
        
        except Exception as e:
            if 'not enabled' in str(e).lower() or 'AccessDenied' in str(e):
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'Macie Automated Discovery',
                    'resource_id': f"macie-auto-discovery-{region}",
                    'status': 'NON_COMPLIANT',
                    'compliance_status': 'FAIL',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable automated sensitive data discovery in Amazon Macie'),
                    'details': {
                        'macie_status': 'NOT_ENABLED',
                        'automated_discovery_status': 'UNAVAILABLE',
                        'message': 'Amazon Macie is not enabled'
                    }
                }
                findings.append(finding)
                return findings
            else:
                raise e
        
        # Check automated discovery configuration
        try:
            discovery_config = macie2_client.get_automated_discovery_configuration()
            
            classification_scope_id = discovery_config.get('classificationScopeId', 'Not configured')
            disabled_at = discovery_config.get('disabledAt', None)
            first_enabled_at = discovery_config.get('firstEnabledAt', None)
            last_updated_at = discovery_config.get('lastUpdatedAt', None)
            sensitivity_inspection_template_id = discovery_config.get('sensitivityInspectionTemplateId', 'Not configured')
            status = discovery_config.get('status', 'UNKNOWN')
            
            # Determine compliance status
            if status == 'ENABLED':
                compliance_status_result = 'COMPLIANT'
                compliance_check = 'PASS'
                message = "Macie automated sensitive data discovery is enabled"
            else:
                compliance_status_result = 'NON_COMPLIANT'
                compliance_check = 'FAIL'
                message = f"Macie automated sensitive data discovery is {status}"
            
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'Macie Automated Discovery',
                'resource_id': f"macie-auto-discovery-{region}",
                'status': compliance_status_result,
                'compliance_status': compliance_check,
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable automated sensitive data discovery in Amazon Macie'),
                'details': {
                    'macie_status': 'ENABLED',
                    'automated_discovery_status': status,
                    'classification_scope_id': classification_scope_id,
                    'sensitivity_inspection_template_id': sensitivity_inspection_template_id,
                    'first_enabled_at': str(first_enabled_at) if first_enabled_at else 'Never',
                    'last_updated_at': str(last_updated_at) if last_updated_at else 'Never',
                    'disabled_at': str(disabled_at) if disabled_at else 'Never',
                    'message': message
                }
            }
            
        except macie2_client.exceptions.AccessDeniedException:
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'Macie Automated Discovery',
                'resource_id': f"macie-auto-discovery-{region}",
                'status': 'ERROR',
                'compliance_status': 'ERROR',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable automated sensitive data discovery in Amazon Macie'),
                'error': 'Access denied when checking automated discovery configuration',
                'details': {
                    'macie_status': 'ENABLED',
                    'automated_discovery_status': 'ACCESS_DENIED',
                    'message': 'Insufficient permissions to check automated discovery configuration'
                }
            }
            
        except Exception as e:
            if 'not configured' in str(e).lower():
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'Macie Automated Discovery',
                    'resource_id': f"macie-auto-discovery-{region}",
                    'status': 'NON_COMPLIANT',
                    'compliance_status': 'FAIL',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable automated sensitive data discovery in Amazon Macie'),
                    'details': {
                        'macie_status': 'ENABLED',
                        'automated_discovery_status': 'NOT_CONFIGURED',
                        'message': 'Automated sensitive data discovery is not configured'
                    }
                }
            else:
                raise e
        
        findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in macie_automated_sensitive_data_discovery_enabled check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'Macie Automated Discovery',
            'resource_id': 'Unknown',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable automated sensitive data discovery in Amazon Macie'),
            'error': str(e),
            'details': {
                'error_message': str(e),
                'check_type': 'macie_automated_sensitive_data_discovery_enabled'
            }
        })
        
    return findings

def macie_automated_sensitive_data_discovery_enabled(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=macie_automated_sensitive_data_discovery_enabled_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = macie_automated_sensitive_data_discovery_enabled(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

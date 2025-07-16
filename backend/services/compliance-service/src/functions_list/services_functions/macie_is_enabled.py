#!/usr/bin/env python3
"""
aws_foundational_security_best_practices_aws - macie_is_enabled

This control checks whether Amazon Macie is enabled in the AWS account to help discover and protect sensitive data.
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
                    'recommendation': entry.get('Recommendation', 'Enable Amazon Macie to discover and protect sensitive data')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'aws_foundational_security_best_practices_aws',
        'function_name': 'macie_is_enabled',
        'id': 'Macie.1',
        'name': 'Amazon Macie should be enabled',
        'description': 'This control checks whether Amazon Macie is enabled in the AWS account to help discover and protect sensitive data.',
        'api_function': 'client = boto3.client("macie2")',
        'user_function': 'get_macie_session()',
        'risk_level': 'HIGH',
        'recommendation': 'Enable Amazon Macie to discover and protect sensitive data'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('macie_is_enabled')

def macie_is_enabled_check(macie2_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for macie_is_enabled.
    
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
        logger.info("Checking if Amazon Macie is enabled...")
        
        # Check if Macie is enabled by trying to get the Macie session
        try:
            response = macie2_client.get_macie_session()
            
            # If we get a response, Macie is enabled
            macie_status = response.get('status', 'UNKNOWN')
            finding_type = response.get('findingPublishingFrequency', 'UNKNOWN')
            service_role = response.get('serviceRole', 'Not configured')
            
            if macie_status == 'ENABLED':
                status = 'COMPLIANT'
                compliance_status = 'PASS'
                message = "Amazon Macie is enabled and active"
            elif macie_status == 'PAUSED':
                status = 'NON_COMPLIANT'
                compliance_status = 'FAIL'
                message = "Amazon Macie is enabled but paused"
            else:
                status = 'NON_COMPLIANT'
                compliance_status = 'FAIL'
                message = f"Amazon Macie status is {macie_status}"
            
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'Macie Session',
                'resource_id': f"macie-session-{region}",
                'status': status,
                'compliance_status': compliance_status,
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable Amazon Macie to discover and protect sensitive data'),
                'details': {
                    'macie_status': macie_status,
                    'finding_publishing_frequency': finding_type,
                    'service_role': service_role,
                    'created_at': response.get('createdAt', 'Unknown'),
                    'updated_at': response.get('updatedAt', 'Unknown'),
                    'message': message
                }
            }
            
        except macie2_client.exceptions.AccessDeniedException:
            # Macie is not enabled or insufficient permissions
            status = 'NON_COMPLIANT'
            compliance_status = 'FAIL'
            message = "Amazon Macie is not enabled or access denied"
            
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'Macie Session',
                'resource_id': f"macie-session-{region}",
                'status': status,
                'compliance_status': compliance_status,
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable Amazon Macie to discover and protect sensitive data'),
                'details': {
                    'macie_status': 'NOT_ENABLED',
                    'message': message
                }
            }
            
        except Exception as e:
            # Handle other exceptions
            if 'Macie is not available' in str(e) or 'not enabled' in str(e).lower():
                status = 'NON_COMPLIANT'
                compliance_status = 'FAIL'
                message = "Amazon Macie is not enabled in this region"
                
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'Macie Session',
                    'resource_id': f"macie-session-{region}",
                    'status': status,
                    'compliance_status': compliance_status,
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable Amazon Macie to discover and protect sensitive data'),
                    'details': {
                        'macie_status': 'NOT_ENABLED',
                        'message': message
                    }
                }
            else:
                raise e
        
        findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in macie_is_enabled check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'Macie Session',
            'resource_id': 'Unknown',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable Amazon Macie to discover and protect sensitive data'),
            'error': str(e),
            'details': {
                'error_message': str(e),
                'check_type': 'macie_is_enabled'
            }
        })
        
    return findings

def macie_is_enabled(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=macie_is_enabled_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = macie_is_enabled(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

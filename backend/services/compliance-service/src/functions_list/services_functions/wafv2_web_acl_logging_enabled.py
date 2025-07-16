#!/usr/bin/env python3
"""
pci_3.2.1_aws - wafv2_web_acl_logging_enabled

It is critical to have a process or system that links user access to system components accessed. This system generates audit logs and provides the ability to trace back suspicious activity to a specific user. This control verifies, through observation and interviewing the system administrator, that: audit trails are enabled and active for system components, access to system components is linked to individual users.
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
        'compliance_name': 'pci_3.2.1_aws',
        'function_name': 'wafv2_web_acl_logging_enabled',
        'id': 'WAF-001',
        'name': 'WAFv2 Web ACL Logging Configuration',
        'description': 'Verify that WAFv2 Web ACLs have logging enabled for audit trail purposes',
        'api_function': 'client=boto3.client("wafv2")',
        'user_function': 'get_logging_configuration()',
        'risk_level': 'HIGH',
        'recommendation': 'Enable logging for all WAFv2 Web ACLs to maintain audit trails'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('wafv2_web_acl_logging_enabled')

def wafv2_web_acl_logging_enabled_check(wafv2_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for wafv2_web_acl_logging_enabled.
    
    Args:
        wafv2_client: Boto3 WAFv2 client (auto-created by framework)
        region (str): AWS region (auto-managed by framework)
        profile (str): AWS profile name (auto-managed by framework)
        logger: Logger instance (auto-configured by framework)
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    try:
        # Get all Web ACLs for both CLOUDFRONT and REGIONAL scopes
        scopes = ['CLOUDFRONT', 'REGIONAL']
        
        for scope in scopes:
            try:
                # List Web ACLs for this scope
                response = wafv2_client.list_web_acls(Scope=scope)
                web_acls = response.get('WebACLs', [])
                
                for web_acl in web_acls:
                    web_acl_id = web_acl.get('Id', 'Unknown')
                    web_acl_name = web_acl.get('Name', 'Unknown')
                    web_acl_arn = web_acl.get('ARN', 'Unknown')
                    
                    try:
                        # Check logging configuration for this Web ACL
                        logging_response = wafv2_client.get_logging_configuration(
                            ResourceArn=web_acl_arn
                        )
                        
                        logging_config = logging_response.get('LoggingConfiguration', {})
                        
                        if logging_config:
                            # Logging is enabled
                            log_destinations = logging_config.get('LogDestinationConfigs', [])
                            redacted_fields = logging_config.get('RedactedFields', [])
                            
                            finding = {
                                'region': region,
                                'profile': profile,
                                'resource_type': 'WAFv2_WebACL',
                                'resource_id': f"{web_acl_name} ({web_acl_id})",
                                'status': 'COMPLIANT',
                                'compliance_status': 'PASS',
                                'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                                'recommendation': COMPLIANCE_DATA.get('recommendation', 'Maintain logging configuration'),
                                'details': {
                                    'web_acl_name': web_acl_name,
                                    'web_acl_id': web_acl_id,
                                    'scope': scope,
                                    'logging_enabled': True,
                                    'log_destinations': log_destinations,
                                    'redacted_fields_count': len(redacted_fields)
                                }
                            }
                        else:
                            # This shouldn't happen if get_logging_configuration succeeds
                            finding = {
                                'region': region,
                                'profile': profile,
                                'resource_type': 'WAFv2_WebACL',
                                'resource_id': f"{web_acl_name} ({web_acl_id})",
                                'status': 'NON_COMPLIANT',
                                'compliance_status': 'FAIL',
                                'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                                'recommendation': 'Enable logging for this Web ACL',
                                'details': {
                                    'web_acl_name': web_acl_name,
                                    'web_acl_id': web_acl_id,
                                    'scope': scope,
                                    'logging_enabled': False,
                                    'issue': 'No logging configuration found'
                                }
                            }
                            
                    except wafv2_client.exceptions.WAFNonexistentItemException:
                        # No logging configuration exists for this Web ACL
                        finding = {
                            'region': region,
                            'profile': profile,
                            'resource_type': 'WAFv2_WebACL',
                            'resource_id': f"{web_acl_name} ({web_acl_id})",
                            'status': 'NON_COMPLIANT',
                            'compliance_status': 'FAIL',
                            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                            'recommendation': 'Enable logging for this Web ACL',
                            'details': {
                                'web_acl_name': web_acl_name,
                                'web_acl_id': web_acl_id,
                                'scope': scope,
                                'logging_enabled': False,
                                'issue': 'Logging not configured'
                            }
                        }
                    except Exception as logging_error:
                        logger.error(f"Error checking logging for Web ACL {web_acl_id}: {logging_error}")
                        finding = {
                            'region': region,
                            'profile': profile,
                            'resource_type': 'WAFv2_WebACL',
                            'resource_id': f"{web_acl_name} ({web_acl_id})",
                            'status': 'ERROR',
                            'compliance_status': 'ERROR',
                            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                            'recommendation': 'Review Web ACL logging configuration',
                            'error': str(logging_error),
                            'details': {
                                'web_acl_name': web_acl_name,
                                'web_acl_id': web_acl_id,
                                'scope': scope
                            }
                        }
                    
                    findings.append(finding)
                    
            except Exception as scope_error:
                logger.error(f"Error listing Web ACLs for scope {scope}: {scope_error}")
                # Continue with next scope
                continue
        
    except Exception as e:
        logger.error(f"Error in wafv2_web_acl_logging_enabled check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'WAFv2_WebACL',
            'status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Review WAFv2 configuration'),
            'error': str(e)
        })
        
    return findings

def wafv2_web_acl_logging_enabled(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=wafv2_web_acl_logging_enabled_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = wafv2_web_acl_logging_enabled(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

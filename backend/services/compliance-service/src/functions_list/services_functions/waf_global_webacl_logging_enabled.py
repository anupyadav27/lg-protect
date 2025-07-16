#!/usr/bin/env python3
"""
iso27001_2022_aws - waf_global_webacl_logging_enabled

Networks, systems and applications should be monitored for anomalous behaviour and appropriate actions taken to evaluate potential information security incidents.
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
                    'recommendation': entry.get('Recommendation', 'Enable logging for WAF WebACLs to monitor security events and detect anomalous behavior')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'iso27001_2022_aws',
        'function_name': 'waf_global_webacl_logging_enabled',
        'id': 'ISO27001_WAF_LOGGING',
        'name': 'WAF Global WebACL Logging Check',
        'description': 'Networks, systems and applications should be monitored for anomalous behaviour and appropriate actions taken to evaluate potential information security incidents.',
        'api_function': 'client=boto3.client(\'wafv2\')',
        'user_function': 'get_logging_configuration()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Enable logging for WAF WebACLs to monitor security events and detect anomalous behavior'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('waf_global_webacl_logging_enabled')

def waf_global_webacl_logging_enabled_check(wafv2_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for waf_global_webacl_logging_enabled.
    
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
        # List WebACLs with CLOUDFRONT scope (global)
        webacls_response = wafv2_client.list_web_acls(Scope='CLOUDFRONT')
        webacls = webacls_response.get('WebACLs', [])
        
        if not webacls:
            logger.info(f"No global WAF WebACLs found in region {region}")
            return findings
        
        for webacl_summary in webacls:
            webacl_name = webacl_summary.get('Name', '')
            webacl_id = webacl_summary.get('Id', '')
            webacl_arn = webacl_summary.get('ARN', '')
            
            try:
                # Check logging configuration for this WebACL
                logging_response = wafv2_client.get_logging_configuration(
                    ResourceArn=webacl_arn
                )
                
                logging_config = logging_response.get('LoggingConfiguration', {})
                
                # Extract logging details
                log_destination_configs = logging_config.get('LogDestinationConfigs', [])
                redacted_fields = logging_config.get('RedactedFields', [])
                managed_by_firewall_manager = logging_config.get('ManagedByFirewallManager', False)
                logging_filter = logging_config.get('LoggingFilter', {})
                
                is_logging_enabled = len(log_destination_configs) > 0
                
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'WAFv2WebACL',
                    'resource_id': webacl_arn,
                    'status': 'COMPLIANT' if is_logging_enabled else 'NON_COMPLIANT',
                    'compliance_status': 'PASS' if is_logging_enabled else 'FAIL',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable logging for WAF WebACLs'),
                    'details': {
                        'webacl_name': webacl_name,
                        'webacl_id': webacl_id,
                        'webacl_arn': webacl_arn,
                        'logging_enabled': is_logging_enabled,
                        'log_destination_configs': log_destination_configs,
                        'log_destinations_count': len(log_destination_configs),
                        'redacted_fields_count': len(redacted_fields),
                        'managed_by_firewall_manager': managed_by_firewall_manager,
                        'has_logging_filter': bool(logging_filter),
                        'scope': 'CLOUDFRONT'
                    }
                }
                
                findings.append(finding)
                
                if is_logging_enabled:
                    logger.info(f"WAF global WebACL {webacl_name} has logging enabled with {len(log_destination_configs)} destinations")
                else:
                    logger.warning(f"WAF global WebACL {webacl_name} does not have logging enabled")
                    
            except wafv2_client.exceptions.WAFNonexistentItemException:
                # No logging configuration exists for this WebACL
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'WAFv2WebACL',
                    'resource_id': webacl_arn,
                    'status': 'NON_COMPLIANT',
                    'compliance_status': 'FAIL',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable logging for WAF WebACLs'),
                    'details': {
                        'webacl_name': webacl_name,
                        'webacl_id': webacl_id,
                        'webacl_arn': webacl_arn,
                        'logging_enabled': False,
                        'log_destination_configs': [],
                        'log_destinations_count': 0,
                        'scope': 'CLOUDFRONT',
                        'issue': 'No logging configuration found'
                    }
                }
                
                findings.append(finding)
                logger.warning(f"WAF global WebACL {webacl_name} has no logging configuration")
                
            except Exception as webacl_error:
                logger.error(f"Error checking logging for WebACL {webacl_name}: {webacl_error}")
                findings.append({
                    'region': region,
                    'profile': profile,
                    'resource_type': 'WAFv2WebACL',
                    'resource_id': webacl_arn,
                    'status': 'ERROR',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable logging for WAF WebACLs'),
                    'error': str(webacl_error)
                })
        
    except Exception as e:
        logger.error(f"Error in waf_global_webacl_logging_enabled check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'WAFv2WebACL',
            'status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable logging for WAF WebACLs'),
            'error': str(e)
        })
        
    return findings

def waf_global_webacl_logging_enabled(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=waf_global_webacl_logging_enabled_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = waf_global_webacl_logging_enabled(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

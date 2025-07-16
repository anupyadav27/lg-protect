#!/usr/bin/env python3
"""
iso27001_2022_aws - wafv2_webacl_logging_enabled

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
                    'recommendation': entry.get('Recommendation', 'Review and remediate as needed')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'iso27001_2022_aws',
        'function_name': 'wafv2_webacl_logging_enabled',
        'id': 'A.12.4.1',
        'name': 'WAFv2 Web ACL should have logging enabled',
        'description': 'Networks, systems and applications should be monitored for anomalous behaviour and appropriate actions taken to evaluate potential information security incidents',
        'api_function': 'client = boto3.client("wafv2")',
        'user_function': 'list_web_acls(), get_logging_configuration()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Enable logging for WAFv2 Web ACLs to monitor security events and anomalous behavior'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('wafv2_webacl_logging_enabled')

def wafv2_webacl_logging_enabled_check(wafv2_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for wafv2_webacl_logging_enabled.
    
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
        logger.info(f"Checking WAFv2 Web ACL logging configuration in region {region}")
        
        # WAFv2 supports both REGIONAL and CLOUDFRONT scopes
        scopes = ['REGIONAL', 'CLOUDFRONT']
        
        for scope in scopes:
            try:
                # Note: CLOUDFRONT scope is only available in us-east-1
                if scope == 'CLOUDFRONT' and region != 'us-east-1':
                    continue
                    
                logger.info(f"Checking {scope} Web ACLs in region {region}")
                
                # List all Web ACLs for this scope
                web_acls_response = wafv2_client.list_web_acls(Scope=scope)
                web_acls = web_acls_response.get('WebACLs', [])
                
                if not web_acls:
                    logger.info(f"No {scope} Web ACLs found in region {region}")
                    continue
                
                for web_acl in web_acls:
                    web_acl_name = web_acl.get('Name', 'unknown')
                    web_acl_id = web_acl.get('Id', 'unknown')
                    web_acl_arn = web_acl.get('ARN', 'unknown')
                    description = web_acl.get('Description', '')
                    
                    try:
                        # Check logging configuration for this Web ACL
                        logging_response = wafv2_client.get_logging_configuration(
                            ResourceArn=web_acl_arn
                        )
                        
                        logging_config = logging_response.get('LoggingConfiguration', {})
                        
                        if logging_config:
                            # Logging is enabled - extract configuration details
                            log_destination_configs = logging_config.get('LogDestinationConfigs', [])
                            redacted_fields = logging_config.get('RedactedFields', [])
                            managed_by_firewall_manager = logging_config.get('ManagedByFirewallManager', False)
                            logging_filter = logging_config.get('LoggingFilter', {})
                            
                            # Compliant: Logging is enabled
                            finding = {
                                'region': region,
                                'profile': profile,
                                'resource_type': f'WAFv2 Web ACL ({scope})',
                                'resource_id': web_acl_name,
                                'status': 'COMPLIANT',
                                'compliance_status': 'PASS',
                                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                                'recommendation': COMPLIANCE_DATA.get('recommendation', 'Logging is properly enabled'),
                                'details': {
                                    'web_acl_name': web_acl_name,
                                    'web_acl_id': web_acl_id,
                                    'web_acl_arn': web_acl_arn,
                                    'scope': scope,
                                    'description': description,
                                    'logging_enabled': True,
                                    'log_destinations': log_destination_configs,
                                    'log_destinations_count': len(log_destination_configs),
                                    'redacted_fields': redacted_fields,
                                    'redacted_fields_count': len(redacted_fields),
                                    'managed_by_firewall_manager': managed_by_firewall_manager,
                                    'logging_filter': logging_filter,
                                    'has_logging_filter': bool(logging_filter)
                                }
                            }
                        else:
                            # Should not reach here if logging is properly configured
                            finding = {
                                'region': region,
                                'profile': profile,
                                'resource_type': f'WAFv2 Web ACL ({scope})',
                                'resource_id': web_acl_name,
                                'status': 'NON_COMPLIANT',
                                'compliance_status': 'FAIL',
                                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                                'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable logging for this Web ACL'),
                                'details': {
                                    'web_acl_name': web_acl_name,
                                    'web_acl_id': web_acl_id,
                                    'web_acl_arn': web_acl_arn,
                                    'scope': scope,
                                    'description': description,
                                    'logging_enabled': False,
                                    'issue': 'Logging configuration exists but appears to be empty',
                                    'security_risk': 'Without logging, security events and attacks cannot be monitored or analyzed',
                                    'remediation_steps': [
                                        'Navigate to WAF & Shield console',
                                        'Select the Web ACL',
                                        'Go to Logging and metrics tab',
                                        'Enable logging',
                                        'Configure log destination (S3, CloudWatch Logs, or Kinesis Data Firehose)',
                                        'Configure field redaction if needed',
                                        'Test logging functionality'
                                    ]
                                }
                            }
                            
                    except wafv2_client.exceptions.WAFNonexistentItemException:
                        # No logging configuration exists for this Web ACL
                        finding = {
                            'region': region,
                            'profile': profile,
                            'resource_type': f'WAFv2 Web ACL ({scope})',
                            'resource_id': web_acl_name,
                            'status': 'NON_COMPLIANT',
                            'compliance_status': 'FAIL',
                            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable logging for this Web ACL'),
                            'details': {
                                'web_acl_name': web_acl_name,
                                'web_acl_id': web_acl_id,
                                'web_acl_arn': web_acl_arn,
                                'scope': scope,
                                'description': description,
                                'logging_enabled': False,
                                'issue': 'No logging configuration found for this Web ACL',
                                'security_risk': 'Without logging, security events, attacks, and anomalous behavior cannot be monitored',
                                'remediation_steps': [
                                    'Navigate to WAF & Shield console',
                                    'Select the Web ACL',
                                    'Go to Logging and metrics tab',
                                    'Enable logging',
                                    'Choose log destination:',
                                    '  - Amazon S3 bucket for long-term storage',
                                    '  - CloudWatch Logs for real-time monitoring',
                                    '  - Kinesis Data Firehose for streaming analytics',
                                    'Configure sampling rate and field redaction',
                                    'Set up CloudWatch alarms for critical events',
                                    'Test logging and verify log delivery'
                                ]
                            }
                        }
                        
                    except Exception as e:
                        logger.warning(f"Error checking logging for Web ACL {web_acl_name}: {e}")
                        finding = {
                            'region': region,
                            'profile': profile,
                            'resource_type': f'WAFv2 Web ACL ({scope})',
                            'resource_id': web_acl_name,
                            'status': 'ERROR',
                            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Review Web ACL configuration'),
                            'details': {
                                'web_acl_name': web_acl_name,
                                'web_acl_id': web_acl_id,
                                'web_acl_arn': web_acl_arn,
                                'scope': scope,
                                'error': str(e)
                            }
                        }
                    
                    findings.append(finding)
                    
            except Exception as e:
                logger.error(f"Error listing {scope} Web ACLs in {region}: {e}")
                findings.append({
                    'region': region,
                    'profile': profile,
                    'resource_type': f'WAFv2 Web ACL ({scope})',
                    'status': 'ERROR',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Review WAFv2 configuration'),
                    'error': str(e)
                })
        
        if not findings:
            logger.info(f"No WAFv2 Web ACLs found in region {region}")
        
    except Exception as e:
        logger.error(f"Error in wafv2_webacl_logging_enabled check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'WAFv2 Web ACL',
            'status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Review and remediate as needed'),
            'error': str(e)
        })
        
    return findings

def wafv2_webacl_logging_enabled(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=wafv2_webacl_logging_enabled_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = wafv2_webacl_logging_enabled(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

#!/usr/bin/env python3
"""
aws_foundational_security_best_practices_aws - mq_broker_active_deployment_mode

This control checks whether Amazon MQ brokers are deployed in active/standby multi-AZ deployment mode for high availability.
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
                    'recommendation': entry.get('Recommendation', 'Deploy MQ brokers in active/standby mode for high availability')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'aws_foundational_security_best_practices_aws',
        'function_name': 'mq_broker_active_deployment_mode',
        'id': 'MQ.2',
        'name': 'Amazon MQ brokers should use active/standby deployment mode',
        'description': 'This control checks whether Amazon MQ brokers are deployed in active/standby multi-AZ deployment mode for high availability.',
        'api_function': 'client = boto3.client("mq")',
        'user_function': 'list_brokers(), describe_broker()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Deploy MQ brokers in active/standby mode for high availability'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('mq_broker_active_deployment_mode')

def mq_broker_active_deployment_mode_check(mq_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for mq_broker_active_deployment_mode.
    
    Args:
        mq_client: Boto3 MQ client (auto-created by framework)
        region (str): AWS region (auto-managed by framework)
        profile (str): AWS profile name (auto-managed by framework)
        logger: Logger instance (auto-configured by framework)
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    try:
        logger.info("Checking MQ brokers for active deployment mode...")
        
        # Get all MQ brokers
        response = mq_client.list_brokers()
        brokers = response.get('BrokerSummaries', [])
        
        if not brokers:
            logger.info("No MQ brokers found in this region")
            return findings
        
        for broker_summary in brokers:
            broker_id = broker_summary.get('BrokerId', 'Unknown')
            broker_name = broker_summary.get('BrokerName', 'Unknown')
            
            try:
                # Get detailed broker information
                broker_details = mq_client.describe_broker(BrokerId=broker_id)
                
                # Check deployment mode
                deployment_mode = broker_details.get('DeploymentMode', 'SINGLE_INSTANCE')
                engine_type = broker_details.get('EngineType', 'Unknown')
                
                # Determine compliance status
                # ACTIVE_STANDBY_MULTI_AZ is the preferred deployment mode for high availability
                if deployment_mode == 'ACTIVE_STANDBY_MULTI_AZ':
                    status = 'COMPLIANT'
                    compliance_status = 'PASS'
                    message = "MQ broker is deployed in active/standby multi-AZ mode"
                elif deployment_mode == 'CLUSTER_MULTI_AZ':
                    status = 'COMPLIANT'
                    compliance_status = 'PASS'
                    message = "MQ broker is deployed in cluster multi-AZ mode (higher availability)"
                else:
                    status = 'NON_COMPLIANT'
                    compliance_status = 'FAIL'
                    message = f"MQ broker is deployed in {deployment_mode} mode, not active/standby mode"
                
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'MQ Broker',
                    'resource_id': broker_id,
                    'status': status,
                    'compliance_status': compliance_status,
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Deploy MQ brokers in active/standby mode for high availability'),
                    'details': {
                        'broker_id': broker_id,
                        'broker_name': broker_name,
                        'deployment_mode': deployment_mode,
                        'engine_type': engine_type,
                        'engine_version': broker_details.get('EngineVersion', 'Unknown'),
                        'broker_state': broker_details.get('BrokerState', 'Unknown'),
                        'instance_type': broker_details.get('HostInstanceType', 'Unknown'),
                        'subnet_ids': broker_details.get('SubnetIds', []),
                        'message': message
                    }
                }
                
                findings.append(finding)
                
            except Exception as e:
                logger.error(f"Error describing broker {broker_id}: {e}")
                findings.append({
                    'region': region,
                    'profile': profile,
                    'resource_type': 'MQ Broker',
                    'resource_id': broker_id,
                    'status': 'ERROR',
                    'compliance_status': 'ERROR',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Deploy MQ brokers in active/standby mode for high availability'),
                    'error': str(e),
                    'details': {
                        'broker_id': broker_id,
                        'broker_name': broker_name,
                        'error_message': str(e)
                    }
                })
            
    except Exception as e:
        logger.error(f"Error in mq_broker_active_deployment_mode check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'MQ Broker',
            'resource_id': 'Unknown',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Deploy MQ brokers in active/standby mode for high availability'),
            'error': str(e),
            'details': {
                'error_message': str(e),
                'check_type': 'mq_broker_active_deployment_mode'
            }
        })
        
    return findings

def mq_broker_active_deployment_mode(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=mq_broker_active_deployment_mode_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = mq_broker_active_deployment_mode(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

#!/usr/bin/env python3
"""
aws_foundational_security_best_practices_aws - vpc_flow_logs_enabled

VPC Flow Logs should be enabled
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
                    'recommendation': entry.get('Recommendation', 'Enable VPC Flow Logs for network monitoring and security analysis')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'aws_foundational_security_best_practices_aws',
        'function_name': 'vpc_flow_logs_enabled',
        'id': 'EC2.6',
        'name': 'VPC Flow Logs should be enabled',
        'description': 'This control checks whether VPC Flow Logs are enabled for VPCs.',
        'api_function': 'client = boto3.client(\'ec2\')',
        'user_function': 'describe_vpcs(), describe_flow_logs()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Enable VPC Flow Logs for network monitoring and security analysis'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('vpc_flow_logs_enabled')

def vpc_flow_logs_enabled_check(ec2_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for vpc_flow_logs_enabled.
    
    Args:
        ec2_client: Boto3 EC2 client (auto-created by framework)
        region (str): AWS region (auto-managed by framework)
        profile (str): AWS profile name (auto-managed by framework)
        logger: Logger instance (auto-configured by framework)
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    try:
        # Get all VPCs
        vpcs_response = ec2_client.describe_vpcs()
        vpcs = vpcs_response.get('Vpcs', [])
        
        # Get all flow logs
        flow_logs_response = ec2_client.describe_flow_logs()
        flow_logs = flow_logs_response.get('FlowLogs', [])
        
        # Create a mapping of resource IDs to their flow logs
        resource_flow_logs = {}
        for flow_log in flow_logs:
            resource_id = flow_log.get('ResourceId')
            if resource_id not in resource_flow_logs:
                resource_flow_logs[resource_id] = []
            resource_flow_logs[resource_id].append(flow_log)
        
        for vpc in vpcs:
            vpc_id = vpc['VpcId']
            vpc_cidr = vpc.get('CidrBlock', 'Unknown')
            is_default = vpc.get('IsDefault', False)
            vpc_state = vpc.get('State', 'Unknown')
            
            # Check if VPC has flow logs enabled
            vpc_flow_logs = resource_flow_logs.get(vpc_id, [])
            
            # Filter active flow logs
            active_flow_logs = [fl for fl in vpc_flow_logs if fl.get('FlowLogStatus') == 'ACTIVE']
            
            if active_flow_logs:
                status = 'COMPLIANT'
                compliance_status = 'PASS'
                note = f'VPC has {len(active_flow_logs)} active flow log(s)'
            else:
                status = 'NON_COMPLIANT'
                compliance_status = 'FAIL'
                note = 'VPC does not have active flow logs enabled'
            
            # Gather flow log details
            flow_log_details = []
            for flow_log in active_flow_logs:
                flow_log_details.append({
                    'flow_log_id': flow_log.get('FlowLogId'),
                    'status': flow_log.get('FlowLogStatus'),
                    'traffic_type': flow_log.get('TrafficType'),
                    'log_destination_type': flow_log.get('LogDestinationType'),
                    'log_destination': flow_log.get('LogDestination'),
                    'log_group_name': flow_log.get('LogGroupName'),
                    'creation_time': flow_log.get('CreationTime').isoformat() if flow_log.get('CreationTime') else None
                })
            
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'VPC',
                'resource_id': vpc_id,
                'status': status,
                'compliance_status': compliance_status,
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable VPC Flow Logs for network monitoring and security analysis'),
                'details': {
                    'vpc_id': vpc_id,
                    'vpc_cidr': vpc_cidr,
                    'is_default_vpc': is_default,
                    'vpc_state': vpc_state,
                    'has_flow_logs': len(active_flow_logs) > 0,
                    'active_flow_logs_count': len(active_flow_logs),
                    'total_flow_logs_count': len(vpc_flow_logs),
                    'flow_logs': flow_log_details,
                    'note': note
                }
            }
            
            findings.append(finding)
        
        if not vpcs:
            logger.info(f"No VPCs found in region {region}")
        
    except Exception as e:
        logger.error(f"Error in vpc_flow_logs_enabled check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'VPC',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable VPC Flow Logs for network monitoring and security analysis'),
            'error': str(e)
        })
        
    return findings

def vpc_flow_logs_enabled(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=vpc_flow_logs_enabled_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = vpc_flow_logs_enabled(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

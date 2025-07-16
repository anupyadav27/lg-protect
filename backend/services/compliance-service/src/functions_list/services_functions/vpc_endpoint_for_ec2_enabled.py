#!/usr/bin/env python3
"""
iso27001_2022_aws - vpc_endpoint_for_ec2_enabled

Security mechanisms, service levels and service requirements of network services should be identified, implemented and monitored.
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
        'function_name': 'vpc_endpoint_for_ec2_enabled',
        'id': 'VPC-EP-001',
        'name': 'VPC Endpoint for EC2',
        'description': 'Security mechanisms, service levels and service requirements of network services should be identified, implemented and monitored.',
        'api_function': 'client=boto3.client("ec2")',
        'user_function': 'describe_vpc_endpoints()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Enable VPC endpoints for EC2 service to improve security'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('vpc_endpoint_for_ec2_enabled')

def vpc_endpoint_for_ec2_enabled_check(ec2_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for vpc_endpoint_for_ec2_enabled.
    
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
        # Get all VPCs first
        vpcs_response = ec2_client.describe_vpcs()
        vpcs = vpcs_response.get('Vpcs', [])
        
        if not vpcs:
            logger.info(f"No VPCs found in region {region}")
            return findings
        
        # Get all VPC endpoints
        vpc_endpoints_response = ec2_client.describe_vpc_endpoints()
        vpc_endpoints = vpc_endpoints_response.get('VpcEndpoints', [])
        
        # EC2 service names that should have VPC endpoints
        ec2_service_names = [
            f'com.amazonaws.{region}.ec2',
            f'com.amazonaws.{region}.ec2messages',
            f'com.amazonaws.{region}.ssm',
            f'com.amazonaws.{region}.ssmmessages'
        ]
        
        # Group endpoints by VPC
        vpc_endpoints_by_vpc = {}
        for endpoint in vpc_endpoints:
            vpc_id = endpoint.get('VpcId')
            service_name = endpoint.get('ServiceName')
            state = endpoint.get('State')
            
            if vpc_id not in vpc_endpoints_by_vpc:
                vpc_endpoints_by_vpc[vpc_id] = []
            
            vpc_endpoints_by_vpc[vpc_id].append({
                'endpoint_id': endpoint.get('VpcEndpointId'),
                'service_name': service_name,
                'state': state,
                'endpoint_type': endpoint.get('VpcEndpointType'),
                'route_table_ids': endpoint.get('RouteTableIds', []),
                'subnet_ids': endpoint.get('SubnetIds', [])
            })
        
        # Check each VPC for EC2-related endpoints
        for vpc in vpcs:
            vpc_id = vpc.get('VpcId')
            vpc_state = vpc.get('State')
            
            if vpc_state != 'available':
                continue
            
            vpc_endpoints_list = vpc_endpoints_by_vpc.get(vpc_id, [])
            
            # Check for EC2-related service endpoints
            ec2_endpoints = []
            missing_services = []
            
            for service_name in ec2_service_names:
                service_endpoints = [ep for ep in vpc_endpoints_list 
                                  if ep['service_name'] == service_name and ep['state'] == 'available']
                
                if service_endpoints:
                    ec2_endpoints.extend(service_endpoints)
                else:
                    missing_services.append(service_name)
            
            # Determine compliance status
            has_ec2_endpoint = any(ep['service_name'] == f'com.amazonaws.{region}.ec2' for ep in ec2_endpoints)
            has_minimal_endpoints = len(ec2_endpoints) > 0
            
            if has_ec2_endpoint and len(missing_services) <= 1:
                # VPC has EC2 endpoint and most required services - COMPLIANT
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'VPC_Endpoint',
                    'resource_id': vpc_id,
                    'status': 'COMPLIANT',
                    'compliance_status': 'PASS',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Maintain VPC endpoints for EC2 services'),
                    'details': {
                        'vpc_id': vpc_id,
                        'vpc_state': vpc_state,
                        'total_endpoints': len(vpc_endpoints_list),
                        'ec2_related_endpoints': len(ec2_endpoints),
                        'has_ec2_endpoint': has_ec2_endpoint,
                        'configured_services': [ep['service_name'] for ep in ec2_endpoints],
                        'missing_services': missing_services,
                        'endpoints': ec2_endpoints
                    }
                }
            elif has_minimal_endpoints:
                # VPC has some endpoints but missing key EC2 services - PARTIALLY_COMPLIANT
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'VPC_Endpoint',
                    'resource_id': vpc_id,
                    'status': 'NON_COMPLIANT',
                    'compliance_status': 'FAIL',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                    'recommendation': 'Configure VPC endpoints for all required EC2 services',
                    'details': {
                        'vpc_id': vpc_id,
                        'vpc_state': vpc_state,
                        'total_endpoints': len(vpc_endpoints_list),
                        'ec2_related_endpoints': len(ec2_endpoints),
                        'has_ec2_endpoint': has_ec2_endpoint,
                        'configured_services': [ep['service_name'] for ep in ec2_endpoints],
                        'missing_services': missing_services,
                        'endpoints': ec2_endpoints,
                        'issue': 'Missing critical EC2 service endpoints'
                    }
                }
            else:
                # VPC has no EC2-related endpoints - NON_COMPLIANT
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'VPC_Endpoint',
                    'resource_id': vpc_id,
                    'status': 'NON_COMPLIANT',
                    'compliance_status': 'FAIL',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                    'recommendation': 'Create VPC endpoints for EC2 services to improve security and reduce data transfer costs',
                    'details': {
                        'vpc_id': vpc_id,
                        'vpc_state': vpc_state,
                        'total_endpoints': len(vpc_endpoints_list),
                        'ec2_related_endpoints': 0,
                        'has_ec2_endpoint': False,
                        'configured_services': [],
                        'missing_services': ec2_service_names,
                        'issue': 'No VPC endpoints configured for EC2 services'
                    }
                }
            
            findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in vpc_endpoint_for_ec2_enabled check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'VPC_Endpoint',
            'status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Review VPC endpoint configuration'),
            'error': str(e)
        })
        
    return findings

def vpc_endpoint_for_ec2_enabled(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=vpc_endpoint_for_ec2_enabled_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = vpc_endpoint_for_ec2_enabled(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

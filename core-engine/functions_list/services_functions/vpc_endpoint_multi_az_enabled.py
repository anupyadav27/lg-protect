#!/usr/bin/env python3
"""
iso27001_2022_aws - vpc_endpoint_multi_az_enabled

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
        compliance_json_path = os.path.join(
            os.path.dirname(__file__), '..', '..', 'compliance_checks.json'
        )
        
        with open(compliance_json_path, 'r') as f:
            compliance_data = json.load(f)
        
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
        
    return {
        'compliance_name': 'iso27001_2022_aws',
        'function_name': 'vpc_endpoint_multi_az_enabled',
        'id': 'EC2.X',
        'name': 'VPC endpoints should be enabled in multiple availability zones',
        'description': 'Security mechanisms, service levels and service requirements of network services should be identified, implemented and monitored.',
        'api_function': 'client = boto3.client("ec2")',
        'user_function': 'describe_vpc_endpoints()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Configure VPC endpoints across multiple availability zones for high availability'
    }

COMPLIANCE_DATA = load_compliance_metadata('vpc_endpoint_multi_az_enabled')

def vpc_endpoint_multi_az_enabled_check(ec2_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for vpc_endpoint_multi_az_enabled.
    
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
        # Get all VPC endpoints
        response = ec2_client.describe_vpc_endpoints()
        vpc_endpoints = response.get('VpcEndpoints', [])
        
        for endpoint in vpc_endpoints:
            endpoint_id = endpoint.get('VpcEndpointId')
            endpoint_type = endpoint.get('VpcEndpointType')
            vpc_id = endpoint.get('VpcId')
            service_name = endpoint.get('ServiceName')
            state = endpoint.get('State')
            
            # Only check Interface and Gateway Load Balancer endpoints (they can have multi-AZ)
            if endpoint_type in ['Interface', 'GatewayLoadBalancer']:
                subnet_ids = endpoint.get('SubnetIds', [])
                
                # Get availability zones for the subnets
                availability_zones = set()
                if subnet_ids:
                    subnets_response = ec2_client.describe_subnets(SubnetIds=subnet_ids)
                    subnets = subnets_response.get('Subnets', [])
                    
                    for subnet in subnets:
                        az = subnet.get('AvailabilityZone')
                        if az:
                            availability_zones.add(az)
                
                # Check if endpoint spans multiple AZs
                multi_az_enabled = len(availability_zones) > 1
                
                status = 'COMPLIANT' if multi_az_enabled else 'NON_COMPLIANT'
                compliance_status = 'PASS' if multi_az_enabled else 'FAIL'
                
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'VPC_ENDPOINT',
                    'resource_id': endpoint_id,
                    'status': status,
                    'compliance_status': compliance_status,
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Configure VPC endpoints across multiple availability zones for high availability'),
                    'details': {
                        'endpoint_id': endpoint_id,
                        'endpoint_type': endpoint_type,
                        'vpc_id': vpc_id,
                        'service_name': service_name,
                        'state': state,
                        'subnet_count': len(subnet_ids),
                        'availability_zones_count': len(availability_zones),
                        'availability_zones': list(availability_zones),
                        'multi_az_enabled': multi_az_enabled
                    }
                }
                
            else:
                # Gateway endpoints don't need multi-AZ (they're regional)
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'VPC_ENDPOINT',
                    'resource_id': endpoint_id,
                    'status': 'COMPLIANT',
                    'compliance_status': 'PASS',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                    'recommendation': 'Gateway endpoints are inherently regional and do not require multi-AZ configuration',
                    'details': {
                        'endpoint_id': endpoint_id,
                        'endpoint_type': endpoint_type,
                        'vpc_id': vpc_id,
                        'service_name': service_name,
                        'state': state,
                        'reason': 'Gateway endpoint - regional by design'
                    }
                }
                
            findings.append(finding)
        
        # If no VPC endpoints found, add informational finding
        if not vpc_endpoints:
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'VPC_ENDPOINT',
                'resource_id': 'NO_ENDPOINTS',
                'status': 'COMPLIANT',
                'compliance_status': 'PASS',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                'recommendation': 'No VPC endpoints found in this region',
                'details': {
                    'message': 'No VPC endpoints found',
                    'endpoints_count': 0
                }
            }
            findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in vpc_endpoint_multi_az_enabled check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'VPC_ENDPOINT',
            'status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Configure VPC endpoints across multiple availability zones for high availability'),
            'error': str(e)
        })
        
    return findings

def vpc_endpoint_multi_az_enabled(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=vpc_endpoint_multi_az_enabled_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    args = setup_command_line_interface(COMPLIANCE_DATA)
    results = vpc_endpoint_multi_az_enabled(
        profile_name=args.profile,
        region_name=args.region
    )
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

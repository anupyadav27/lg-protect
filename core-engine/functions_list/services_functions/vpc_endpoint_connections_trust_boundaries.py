#!/usr/bin/env python3
"""
vpc_endpoint_connections_trust_boundaries - VPC endpoint connections trust boundaries

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
        'function_name': 'vpc_endpoint_connections_trust_boundaries',
        'id': 'EC2.X',
        'name': 'VPC endpoint connections should respect trust boundaries',
        'description': 'Security mechanisms, service levels and service requirements of network services should be identified, implemented and monitored.',
        'api_function': 'client = boto3.client("ec2")',
        'user_function': 'describe_vpc_endpoints()',
        'risk_level': 'HIGH',
        'recommendation': 'Review VPC endpoint connections to ensure they respect organizational trust boundaries'
    }

COMPLIANCE_DATA = load_compliance_metadata('vpc_endpoint_connections_trust_boundaries')

def vpc_endpoint_connections_trust_boundaries_check(ec2_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for vpc_endpoint_connections_trust_boundaries.
    
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
        # Get current account ID for trust boundary analysis
        sts_client = ec2_client._client_config.loader.session.create_client('sts')
        current_account = sts_client.get_caller_identity()['Account']
        
        # Get all VPC endpoints
        response = ec2_client.describe_vpc_endpoints()
        vpc_endpoints = response.get('VpcEndpoints', [])
        
        for endpoint in vpc_endpoints:
            endpoint_id = endpoint.get('VpcEndpointId')
            endpoint_type = endpoint.get('VpcEndpointType')
            vpc_id = endpoint.get('VpcId')
            service_name = endpoint.get('ServiceName')
            state = endpoint.get('State')
            policy_document = endpoint.get('PolicyDocument')
            
            # Analyze trust boundaries
            trust_boundary_violations = []
            has_policy_restrictions = False
            
            # Check if endpoint has a policy document
            if policy_document:
                try:
                    policy = json.loads(policy_document)
                    has_policy_restrictions = True
                    
                    # Check for overly permissive policies
                    for statement in policy.get('Statement', []):
                        principals = statement.get('Principal', {})
                        
                        # Check for wildcard principals
                        if principals == '*':
                            trust_boundary_violations.append({
                                'type': 'wildcard_principal',
                                'description': 'Policy allows access from any principal (*)'
                            })
                        elif isinstance(principals, dict):
                            aws_principals = principals.get('AWS', [])
                            if isinstance(aws_principals, str):
                                aws_principals = [aws_principals]
                            
                            for principal in aws_principals:
                                if principal == '*':
                                    trust_boundary_violations.append({
                                        'type': 'wildcard_aws_principal',
                                        'description': 'Policy allows access from any AWS principal (*)'
                                    })
                                elif ':' in principal and 'root' in principal:
                                    # Check if it's a different account root
                                    account_id = principal.split(':')[4] if len(principal.split(':')) > 4 else ''
                                    if account_id and account_id != current_account:
                                        trust_boundary_violations.append({
                                            'type': 'cross_account_root',
                                            'description': f'Policy allows root access from different account: {account_id}',
                                            'principal': principal
                                        })
                except json.JSONDecodeError:
                    logger.warning(f"Could not parse policy document for endpoint {endpoint_id}")
            else:
                # No policy means default service permissions apply
                has_policy_restrictions = False
            
            # Check service name for external services
            if service_name and not service_name.startswith(f'com.amazonaws.{region}.'):
                # This might be a custom endpoint service
                trust_boundary_violations.append({
                    'type': 'external_service',
                    'description': f'Endpoint connects to external service: {service_name}'
                })
            
            # Determine compliance
            respects_trust_boundaries = len(trust_boundary_violations) == 0 and has_policy_restrictions
            
            status = 'COMPLIANT' if respects_trust_boundaries else 'NON_COMPLIANT'
            compliance_status = 'PASS' if respects_trust_boundaries else 'FAIL'
            
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'VPC_ENDPOINT',
                'resource_id': endpoint_id,
                'status': status,
                'compliance_status': compliance_status,
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                'recommendation': COMPLIANCE_DATA.get('recommendation', 'Review VPC endpoint connections to ensure they respect organizational trust boundaries'),
                'details': {
                    'endpoint_id': endpoint_id,
                    'endpoint_type': endpoint_type,
                    'vpc_id': vpc_id,
                    'service_name': service_name,
                    'state': state,
                    'current_account': current_account,
                    'has_policy_restrictions': has_policy_restrictions,
                    'trust_boundary_violations': trust_boundary_violations,
                    'violations_count': len(trust_boundary_violations),
                    'respects_trust_boundaries': respects_trust_boundaries
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
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                'recommendation': 'No VPC endpoints found in this region',
                'details': {
                    'message': 'No VPC endpoints found',
                    'endpoints_count': 0
                }
            }
            findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in vpc_endpoint_connections_trust_boundaries check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'VPC_ENDPOINT',
            'status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Review VPC endpoint connections to ensure they respect organizational trust boundaries'),
            'error': str(e)
        })
        
    return findings

def vpc_endpoint_connections_trust_boundaries(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=vpc_endpoint_connections_trust_boundaries_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    args = setup_command_line_interface(COMPLIANCE_DATA)
    results = vpc_endpoint_connections_trust_boundaries(
        profile_name=args.profile,
        region_name=args.region
    )
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

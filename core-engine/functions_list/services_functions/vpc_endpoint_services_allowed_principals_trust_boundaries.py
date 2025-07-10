#!/usr/bin/env python3
"""
iso27001_2022_aws - vpc_endpoint_services_allowed_principals_trust_boundaries

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
                    'recommendation': entry.get('Recommendation', 'Review and restrict VPC endpoint service allowed principals to trusted entities only')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'iso27001_2022_aws',
        'function_name': 'vpc_endpoint_services_allowed_principals_trust_boundaries',
        'id': 'ISO27001_VPC_ENDPOINT_PRINCIPALS',
        'name': 'VPC Endpoint Services Allowed Principals Check',
        'description': 'Security mechanisms, service levels and service requirements of network services should be identified, implemented and monitored.',
        'api_function': 'client=boto3.client("ec2")',
        'user_function': 'describe_vpc_endpoint_services()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Review and restrict VPC endpoint service allowed principals to trusted entities only'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('vpc_endpoint_services_allowed_principals_trust_boundaries')

def vpc_endpoint_services_allowed_principals_trust_boundaries_check(ec2_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for vpc_endpoint_services_allowed_principals_trust_boundaries.
    
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
        # Get VPC endpoint services
        services_response = ec2_client.describe_vpc_endpoint_services()
        service_details = services_response.get('ServiceDetails', [])
        service_names = services_response.get('ServiceNames', [])
        
        if not service_details and not service_names:
            logger.info(f"No VPC endpoint services found in region {region}")
            return findings
        
        # Check service details for allowed principals
        for service in service_details:
            service_name = service.get('ServiceName', '')
            service_type = service.get('ServiceType', [])
            service_id = service.get('ServiceId', '')
            owner = service.get('Owner', '')
            
            # Skip AWS-owned services as they are managed by AWS
            if owner == 'amazon':
                continue
            
            try:
                # Get VPC endpoint service configurations for customer-owned services
                if service_id:
                    config_response = ec2_client.describe_vpc_endpoint_service_configurations(
                        ServiceIds=[service_id]
                    )
                    
                    configurations = config_response.get('ServiceConfigurations', [])
                    
                    for config in configurations:
                        service_config_name = config.get('ServiceName', '')
                        acceptance_required = config.get('AcceptanceRequired', True)
                        allowed_principals = config.get('AllowedPrincipals', [])
                        
                        # Analyze trust boundaries
                        trust_boundary_issues = []
                        has_overly_permissive_access = False
                        
                        # Check if acceptance is not required (potential security risk)
                        if not acceptance_required:
                            trust_boundary_issues.append('Service does not require acceptance for connections')
                            has_overly_permissive_access = True
                        
                        # Check allowed principals for overly broad permissions
                        for principal in allowed_principals:
                            if principal == '*':
                                trust_boundary_issues.append('Wildcard (*) principal allows any AWS account')
                                has_overly_permissive_access = True
                            elif ':root' in principal and principal.count(':') < 5:
                                # Check for account-level access (arn:aws:iam::123456789012:root)
                                trust_boundary_issues.append(f'Account-level access granted to {principal}')
                        
                        # Check if no principals are specified but acceptance not required
                        if not allowed_principals and not acceptance_required:
                            trust_boundary_issues.append('No principals specified and acceptance not required')
                            has_overly_permissive_access = True
                        
                        finding = {
                            'region': region,
                            'profile': profile,
                            'resource_type': 'VPCEndpointService',
                            'resource_id': service_config_name or service_id,
                            'status': 'NON_COMPLIANT' if has_overly_permissive_access else 'COMPLIANT',
                            'compliance_status': 'FAIL' if has_overly_permissive_access else 'PASS',
                            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Review and restrict VPC endpoint service principals'),
                            'details': {
                                'service_name': service_config_name,
                                'service_id': service_id,
                                'service_type': service_type,
                                'acceptance_required': acceptance_required,
                                'allowed_principals': allowed_principals,
                                'allowed_principals_count': len(allowed_principals),
                                'has_overly_permissive_access': has_overly_permissive_access,
                                'trust_boundary_issues': trust_boundary_issues,
                                'service_state': config.get('ServiceState', ''),
                                'owner': owner
                            }
                        }
                        
                        findings.append(finding)
                        
                        if has_overly_permissive_access:
                            logger.warning(f"VPC endpoint service {service_config_name} has trust boundary issues: {trust_boundary_issues}")
                        else:
                            logger.info(f"VPC endpoint service {service_config_name} has proper trust boundaries configured")
            
            except Exception as service_error:
                logger.error(f"Error checking service configuration for {service_name}: {service_error}")
                findings.append({
                    'region': region,
                    'profile': profile,
                    'resource_type': 'VPCEndpointService',
                    'resource_id': service_name or service_id,
                    'status': 'ERROR',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Review VPC endpoint service principals'),
                    'error': str(service_error)
                })
        
        # If no customer-owned services found, create an informational finding
        if not any(finding.get('details', {}).get('owner') != 'amazon' for finding in findings):
            logger.info(f"No customer-owned VPC endpoint services found in region {region}")
        
    except Exception as e:
        logger.error(f"Error in vpc_endpoint_services_allowed_principals_trust_boundaries check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'VPCEndpointService',
            'status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Review VPC endpoint service principals'),
            'error': str(e)
        })
        
    return findings

def vpc_endpoint_services_allowed_principals_trust_boundaries(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=vpc_endpoint_services_allowed_principals_trust_boundaries_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = vpc_endpoint_services_allowed_principals_trust_boundaries(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

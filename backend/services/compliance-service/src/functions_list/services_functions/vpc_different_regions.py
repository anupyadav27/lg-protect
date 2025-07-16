#!/usr/bin/env python3
"""
iso27001_2022_aws - vpc_different_regions

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
        'function_name': 'vpc_different_regions',
        'id': 'EC2.X',
        'name': 'VPCs should be distributed across different regions',
        'description': 'Security mechanisms, service levels and service requirements of network services should be identified, implemented and monitored.',
        'api_function': 'client = boto3.client("ec2")',
        'user_function': 'describe_vpcs()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Distribute VPCs across multiple regions for high availability and disaster recovery'
    }

COMPLIANCE_DATA = load_compliance_metadata('vpc_different_regions')

def vpc_different_regions_check(ec2_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for vpc_different_regions.
    
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
        # Get all VPCs in the current region
        response = ec2_client.describe_vpcs()
        vpcs = response.get('Vpcs', [])
        
        # Count non-default VPCs (default VPCs are created automatically)
        custom_vpcs = [vpc for vpc in vpcs if not vpc.get('IsDefault', False)]
        
        # For this check, we need to assess regional distribution
        # Since this runs per region, we'll provide information about VPCs in this region
        # and recommend multi-region deployment
        
        for vpc in custom_vpcs:
            vpc_id = vpc.get('VpcId')
            cidr_block = vpc.get('CidrBlock')
            state = vpc.get('State')
            
            # Each VPC in a single region is technically non-compliant for multi-region requirement
            # However, we'll mark as compliant if it's part of a larger multi-region strategy
            # This would need to be assessed at an organizational level
            
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'VPC',
                'resource_id': vpc_id,
                'status': 'NON_COMPLIANT',  # Default to non-compliant as we can't assess multi-region from single region
                'compliance_status': 'FAIL',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                'recommendation': COMPLIANCE_DATA.get('recommendation', 'Distribute VPCs across multiple regions for high availability and disaster recovery'),
                'details': {
                    'vpc_id': vpc_id,
                    'region': region,
                    'cidr_block': cidr_block,
                    'state': state,
                    'is_default': vpc.get('IsDefault', False),
                    'assessment_note': 'Multi-region VPC distribution requires assessment across all regions'
                }
            }
            
            findings.append(finding)
        
        # Add a summary finding for the region
        region_summary = {
            'region': region,
            'profile': profile,
            'resource_type': 'REGION_SUMMARY',
            'resource_id': f'REGION_{region}',
            'status': 'INFO',
            'compliance_status': 'INFO',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': 'Assess VPC distribution across all AWS regions to ensure proper geographic redundancy',
            'details': {
                'region': region,
                'total_vpcs': len(vpcs),
                'custom_vpcs': len(custom_vpcs),
                'default_vpcs': len(vpcs) - len(custom_vpcs),
                'note': 'For complete compliance assessment, analyze VPC distribution across all regions'
            }
        }
        
        findings.append(region_summary)
        
        # If no custom VPCs found, add informational finding
        if not custom_vpcs:
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'VPC',
                'resource_id': 'NO_CUSTOM_VPCS',
                'status': 'COMPLIANT',
                'compliance_status': 'PASS',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                'recommendation': 'No custom VPCs found in this region',
                'details': {
                    'message': 'No custom VPCs found in this region',
                    'region': region,
                    'custom_vpcs_count': 0
                }
            }
            findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in vpc_different_regions check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'VPC',
            'status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Distribute VPCs across multiple regions for high availability and disaster recovery'),
            'error': str(e)
        })
        
    return findings

def vpc_different_regions(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=vpc_different_regions_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    args = setup_command_line_interface(COMPLIANCE_DATA)
    results = vpc_different_regions(
        profile_name=args.profile,
        region_name=args.region
    )
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

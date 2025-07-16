#!/usr/bin/env python3
"""
ens_rd2022_aws - shield_advanced_protection_in_route53_hosted_zones

Checks if Route53 hosted zones have AWS Shield Advanced protection enabled
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
                    'recommendation': entry.get('Recommendation', 'Enable AWS Shield Advanced protection for Route53 hosted zones to protect against DDoS attacks')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'ens_rd2022_aws',
        'function_name': 'shield_advanced_protection_in_route53_hosted_zones',
        'id': 'ENS_RD2022',
        'name': 'Shield Advanced Protection',
        'description': 'Checks if Route53 hosted zones have AWS Shield Advanced protection enabled',
        'api_function': 'client1=boto3.client(\'route53\'), client2=boto3.client(\'shield\')',
        'user_function': 'list_hosted_zones(), list_protections()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Enable AWS Shield Advanced protection for Route53 hosted zones to protect against DDoS attacks'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('shield_advanced_protection_in_route53_hosted_zones')

def shield_advanced_protection_in_route53_hosted_zones_check(route53_client, shield_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for shield_advanced_protection_in_route53_hosted_zones.
    
    Args:
        route53_client: Boto3 Route53 client (auto-created by framework)
        shield_client: Boto3 Shield client (auto-created by framework)
        region (str): AWS region (auto-managed by framework)
        profile (str): AWS profile name (auto-managed by framework)
        logger: Logger instance (auto-configured by framework)
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    try:
        # Get all hosted zones
        hosted_zones_response = route53_client.list_hosted_zones()
        hosted_zones = hosted_zones_response.get('HostedZones', [])
        
        if not hosted_zones:
            logger.info(f"No hosted zones found in account for region {region}")
            return findings
        
        # Get all Shield Advanced protections
        try:
            protections_response = shield_client.list_protections()
            protections = protections_response.get('Protections', [])
        except Exception as shield_error:
            logger.warning(f"Could not retrieve Shield protections: {shield_error}")
            protections = []
        
        # Create a set of protected resource ARNs for quick lookup
        protected_arns = {protection.get('ResourceArn', '') for protection in protections}
        
        for hosted_zone in hosted_zones:
            zone_id = hosted_zone.get('Id', '').replace('/hostedzone/', '')
            zone_name = hosted_zone.get('Name', '')
            
            # Construct the hosted zone ARN
            zone_arn = f"arn:aws:route53:::hostedzone/{zone_id}"
            
            # Check if this hosted zone is protected by Shield Advanced
            is_protected = zone_arn in protected_arns
            
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'Route53HostedZone',
                'resource_id': zone_id,
                'status': 'COMPLIANT' if is_protected else 'NON_COMPLIANT',
                'compliance_status': 'PASS' if is_protected else 'FAIL',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable AWS Shield Advanced protection for Route53 hosted zones'),
                'details': {
                    'hosted_zone_id': zone_id,
                    'hosted_zone_name': zone_name,
                    'hosted_zone_arn': zone_arn,
                    'shield_advanced_protection': is_protected,
                    'private_zone': hosted_zone.get('Config', {}).get('PrivateZone', False),
                    'record_count': hosted_zone.get('ResourceRecordSetCount', 0)
                }
            }
            
            findings.append(finding)
            
            if is_protected:
                logger.info(f"Hosted zone {zone_name} ({zone_id}) has Shield Advanced protection")
            else:
                logger.warning(f"Hosted zone {zone_name} ({zone_id}) lacks Shield Advanced protection")
        
    except Exception as e:
        logger.error(f"Error in shield_advanced_protection_in_route53_hosted_zones check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'Route53HostedZone',
            'status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable AWS Shield Advanced protection for Route53 hosted zones'),
            'error': str(e)
        })
        
    return findings

def shield_advanced_protection_in_route53_hosted_zones(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=shield_advanced_protection_in_route53_hosted_zones_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = shield_advanced_protection_in_route53_hosted_zones(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

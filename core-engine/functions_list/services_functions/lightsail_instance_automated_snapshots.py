#!/usr/bin/env python3
"""
aws_foundational_security_best_practices_aws - lightsail_instance_automated_snapshots

This control checks whether Lightsail instances have automated snapshots enabled for backup and recovery.
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
                    'recommendation': entry.get('Recommendation', 'Enable automated snapshots for Lightsail instances')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'aws_foundational_security_best_practices_aws',
        'function_name': 'lightsail_instance_automated_snapshots',
        'id': 'Lightsail.3',
        'name': 'Lightsail instances should have automated snapshots enabled',
        'description': 'This control checks whether Lightsail instances have automated snapshots enabled for backup and recovery.',
        'api_function': 'client = boto3.client("lightsail")',
        'user_function': 'get_instances(), get_auto_snapshots()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Enable automated snapshots for Lightsail instances'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('lightsail_instance_automated_snapshots')

def lightsail_instance_automated_snapshots_check(lightsail_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for lightsail_instance_automated_snapshots.
    
    Args:
        lightsail_client: Boto3 Lightsail client (auto-created by framework)
        region (str): AWS region (auto-managed by framework)
        profile (str): AWS profile name (auto-managed by framework)
        logger: Logger instance (auto-configured by framework)
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    try:
        logger.info("Checking Lightsail instances for automated snapshots...")
        
        # Get all instances
        response = lightsail_client.get_instances()
        instances = response.get('instances', [])
        
        if not instances:
            logger.info("No Lightsail instances found in this region")
            return findings
        
        for instance in instances:
            instance_name = instance.get('name', 'Unknown')
            instance_state = instance.get('state', {}).get('name', 'Unknown')
            
            try:
                # Check if automated snapshots are enabled for this instance
                auto_snapshots_response = lightsail_client.get_auto_snapshots(
                    resourceName=instance_name
                )
                
                auto_snapshots = auto_snapshots_response.get('autoSnapshots', [])
                
                # Check if there are any recent auto snapshots
                has_auto_snapshots = len(auto_snapshots) > 0
                
                # Get additional instance details
                resource_type = instance.get('resourceType', 'Instance')
                
                # Determine compliance status
                if has_auto_snapshots:
                    status = 'COMPLIANT'
                    compliance_status = 'PASS'
                    message = f"Instance has {len(auto_snapshots)} automated snapshots configured"
                else:
                    status = 'NON_COMPLIANT'
                    compliance_status = 'FAIL'
                    message = "Instance does not have automated snapshots enabled"
                
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'Lightsail Instance',
                    'resource_id': instance_name,
                    'status': status,
                    'compliance_status': compliance_status,
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable automated snapshots for Lightsail instances'),
                    'details': {
                        'instance_name': instance_name,
                        'instance_state': instance_state,
                        'resource_type': resource_type,
                        'has_auto_snapshots': has_auto_snapshots,
                        'auto_snapshots_count': len(auto_snapshots),
                        'blueprint_id': instance.get('blueprintId', 'Unknown'),
                        'bundle_id': instance.get('bundleId', 'Unknown'),
                        'created_at': str(instance.get('createdAt', 'Unknown')),
                        'location': instance.get('location', {}).get('availabilityZone', 'Unknown'),
                        'message': message
                    }
                }
                
            except Exception as e:
                # Handle cases where auto snapshots check fails
                logger.warning(f"Could not check auto snapshots for instance {instance_name}: {e}")
                
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'Lightsail Instance',
                    'resource_id': instance_name,
                    'status': 'ERROR',
                    'compliance_status': 'ERROR',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable automated snapshots for Lightsail instances'),
                    'error': str(e),
                    'details': {
                        'instance_name': instance_name,
                        'instance_state': instance_state,
                        'error_message': str(e),
                        'message': f"Could not verify automated snapshots status for instance {instance_name}"
                    }
                }
            
            findings.append(finding)
            
    except Exception as e:
        logger.error(f"Error in lightsail_instance_automated_snapshots check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'Lightsail Instance',
            'resource_id': 'Unknown',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable automated snapshots for Lightsail instances'),
            'error': str(e),
            'details': {
                'error_message': str(e),
                'check_type': 'lightsail_instance_automated_snapshots'
            }
        })
        
    return findings

def lightsail_instance_automated_snapshots(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=lightsail_instance_automated_snapshots_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = lightsail_instance_automated_snapshots(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

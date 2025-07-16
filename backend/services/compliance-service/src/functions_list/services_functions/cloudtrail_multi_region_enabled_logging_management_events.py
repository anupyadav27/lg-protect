#!/usr/bin/env python3
"""
cis_1.5_aws - cloudtrail_multi_region_enabled_logging_management_events

Ensure CloudTrail is enabled in all regions
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
        'compliance_name': 'cis_1.5_aws',
        'function_name': 'cloudtrail_multi_region_enabled_logging_management_events',
        'id': '3.1',
        'name': 'CloudTrail Multi-Region Management Events',
        'description': 'Ensure CloudTrail is enabled in all regions',
        'api_function': 'client = boto3.client(\'cloudtrail\')',
        'user_function': 'describe_trails()',
        'risk_level': 'HIGH',
        'recommendation': 'Enable CloudTrail in all regions to ensure comprehensive logging of management events'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('cloudtrail_multi_region_enabled_logging_management_events')

def cloudtrail_multi_region_enabled_logging_management_events_check(cloudtrail_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for cloudtrail_multi_region_enabled_logging_management_events.
    
    Args:
        cloudtrail_client: Boto3 CloudTrail client (auto-created by framework)
        region (str): AWS region (auto-managed by framework)
        profile (str): AWS profile name (auto-managed by framework)
        logger: Logger instance (auto-configured by framework)
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    try:
        # Get all CloudTrail trails (including global trails)
        response = cloudtrail_client.describe_trails(includeShadowTrails=True)
        trails = response.get('trailList', [])
        
        multi_region_trails = []
        single_region_trails = []
        management_event_trails = []
        
        for trail in trails:
            trail_name = trail.get('Name', 'unknown')
            trail_arn = trail.get('TrailARN', 'unknown')
            is_multi_region = trail.get('IsMultiRegionTrail', False)
            include_global_service_events = trail.get('IncludeGlobalServiceEvents', False)
            
            # Get trail status
            try:
                status_response = cloudtrail_client.get_trail_status(Name=trail_name)
                is_logging = status_response.get('IsLogging', False)
            except Exception as e:
                logger.warning(f"Could not get trail status for {trail_name}: {e}")
                is_logging = False
            
            # Get event selectors to check for management events
            try:
                event_selectors_response = cloudtrail_client.get_event_selectors(
                    TrailName=trail_name
                )
                event_selectors = event_selectors_response.get('EventSelectors', [])
                advanced_event_selectors = event_selectors_response.get('AdvancedEventSelectors', [])
                
                has_management_events = False
                
                # Check standard event selectors
                for selector in event_selectors:
                    if selector.get('IncludeManagementEvents', False):
                        has_management_events = True
                        break
                
                # Check advanced event selectors for management events
                if not has_management_events:
                    for advanced_selector in advanced_event_selectors:
                        field_selectors = advanced_selector.get('FieldSelectors', [])
                        for field_selector in field_selectors:
                            if (field_selector.get('Field') == 'eventCategory' and 
                                'Management' in field_selector.get('Equals', [])):
                                has_management_events = True
                                break
                        if has_management_events:
                            break
                
            except Exception as e:
                logger.warning(f"Could not get event selectors for {trail_name}: {e}")
                has_management_events = False
            
            trail_details = {
                'trail_name': trail_name,
                'trail_arn': trail_arn,
                'is_multi_region': is_multi_region,
                'include_global_service_events': include_global_service_events,
                'is_logging': is_logging,
                'has_management_events': has_management_events,
                'home_region': trail.get('HomeRegion', 'unknown'),
                's3_bucket_name': trail.get('S3BucketName', 'unknown')
            }
            
            if is_multi_region:
                multi_region_trails.append(trail_details)
            else:
                single_region_trails.append(trail_details)
            
            if has_management_events and is_logging:
                management_event_trails.append(trail_details)
        
        # Check if there's at least one active multi-region trail with management events
        active_multi_region_management_trails = [
            trail for trail in multi_region_trails 
            if trail['is_logging'] and trail['has_management_events']
        ]
        
        if active_multi_region_management_trails:
            # Compliant if there's at least one active multi-region trail with management events
            for trail in active_multi_region_management_trails:
                findings.append({
                    'region': region,
                    'profile': profile,
                    'resource_type': 'CloudTrail',
                    'resource_id': trail['trail_name'],
                    'status': 'COMPLIANT',
                    'compliance_status': 'PASS',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                    'recommendation': 'Multi-region CloudTrail with management events is properly configured',
                    'details': trail
                })
        else:
            # Non-compliant if no active multi-region trails with management events
            findings.append({
                'region': region,
                'profile': profile,
                'resource_type': 'CloudTrail',
                'resource_id': 'multi-region-management-events',
                'status': 'NON_COMPLIANT',
                'compliance_status': 'FAIL',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable multi-region CloudTrail with management events logging'),
                'details': {
                    'issue': 'No active multi-region CloudTrail trails with management events found',
                    'total_trails': len(trails),
                    'multi_region_trails': len(multi_region_trails),
                    'active_multi_region_management_trails': len(active_multi_region_management_trails),
                    'single_region_trails': len(single_region_trails),
                    'trails_summary': [
                        {
                            'name': trail['trail_name'],
                            'multi_region': trail['is_multi_region'],
                            'logging': trail['is_logging'],
                            'management_events': trail['has_management_events']
                        } for trail in trails[:5]  # Limit for readability
                    ]
                }
            })
        
        # Add individual findings for problematic trails
        for trail in single_region_trails:
            if trail['is_logging'] and trail['has_management_events']:
                findings.append({
                    'region': region,
                    'profile': profile,
                    'resource_type': 'CloudTrail',
                    'resource_id': trail['trail_name'],
                    'status': 'NON_COMPLIANT',
                    'compliance_status': 'FAIL',
                    'risk_level': 'MEDIUM',
                    'recommendation': 'Convert this single-region trail to multi-region or ensure multi-region coverage',
                    'details': trail
                })
        
        for trail in multi_region_trails:
            if not trail['is_logging'] or not trail['has_management_events']:
                findings.append({
                    'region': region,
                    'profile': profile,
                    'resource_type': 'CloudTrail',
                    'resource_id': trail['trail_name'],
                    'status': 'NON_COMPLIANT',
                    'compliance_status': 'FAIL',
                    'risk_level': 'HIGH',
                    'recommendation': 'Enable logging and management events for this multi-region trail',
                    'details': trail
                })
        
    except Exception as e:
        logger.error(f"Error in cloudtrail_multi_region_enabled_logging_management_events check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'CloudTrail',
            'resource_id': f'multi-region-check-{region}',
            'status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Review and remediate as needed'),
            'error': str(e)
        })
        
    return findings

def cloudtrail_multi_region_enabled_logging_management_events(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=cloudtrail_multi_region_enabled_logging_management_events_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = cloudtrail_multi_region_enabled_logging_management_events(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

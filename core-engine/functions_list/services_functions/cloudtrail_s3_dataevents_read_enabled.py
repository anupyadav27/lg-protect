#!/usr/bin/env python3
"""
gdpr_aws - cloudtrail_s3_dataevents_read_enabled

Records of processing activities
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
        'compliance_name': 'gdpr_aws',
        'function_name': 'cloudtrail_s3_dataevents_read_enabled',
        'id': 'article_30',
        'name': 'Records of processing activities',
        'description': 'Records of processing activities',
        'api_function': 'client = boto3.client(\'cloudtrail\')',
        'user_function': 'describe_trails(), get_event_selectors()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Enable CloudTrail data events for S3 read operations to maintain records of data processing activities'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('cloudtrail_s3_dataevents_read_enabled')

def cloudtrail_s3_dataevents_read_enabled_check(cloudtrail_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for cloudtrail_s3_dataevents_read_enabled.
    
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
        # Get all CloudTrail trails
        response = cloudtrail_client.describe_trails()
        trails = response.get('trailList', [])
        
        if not trails:
            findings.append({
                'region': region,
                'profile': profile,
                'resource_type': 'CloudTrail',
                'resource_id': 'no-trails',
                'status': 'NON_COMPLIANT',
                'compliance_status': 'FAIL',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                'recommendation': COMPLIANCE_DATA.get('recommendation', 'Create CloudTrail trails and enable S3 read data events'),
                'details': {
                    'issue': 'No CloudTrail trails found',
                    'trails_count': 0
                }
            })
            return findings
        
        compliant_trails = []
        non_compliant_trails = []
        
        for trail in trails:
            trail_name = trail.get('Name', 'unknown')
            trail_arn = trail.get('TrailARN', 'unknown')
            
            try:
                # Get event selectors for this trail
                event_selectors_response = cloudtrail_client.get_event_selectors(
                    TrailName=trail_name
                )
                
                event_selectors = event_selectors_response.get('EventSelectors', [])
                advanced_event_selectors = event_selectors_response.get('AdvancedEventSelectors', [])
                
                has_s3_read_events = False
                s3_read_details = []
                
                # Check standard event selectors
                for selector in event_selectors:
                    read_write_type = selector.get('ReadWriteType', 'All')
                    data_resources = selector.get('DataResources', [])
                    
                    for data_resource in data_resources:
                        resource_type = data_resource.get('Type', '')
                        values = data_resource.get('Values', [])
                        
                        if resource_type == 'AWS::S3::Object':
                            # Check if read events are enabled
                            if read_write_type in ['ReadOnly', 'All']:
                                has_s3_read_events = True
                                s3_read_details.append({
                                    'type': 'standard_selector',
                                    'read_write_type': read_write_type,
                                    'resource_values': values
                                })
                
                # Check advanced event selectors
                for advanced_selector in advanced_event_selectors:
                    field_selectors = advanced_selector.get('FieldSelectors', [])
                    
                    has_s3_resource = False
                    has_read_events = False
                    
                    for field_selector in field_selectors:
                        field = field_selector.get('Field', '')
                        equals = field_selector.get('Equals', [])
                        
                        if field == 'resources.type' and 'AWS::S3::Object' in equals:
                            has_s3_resource = True
                        
                        if field == 'eventCategory' and 'Data' in equals:
                            # Check for read operations
                            if field == 'readOnly' and 'true' in equals:
                                has_read_events = True
                            elif field == 'eventName':
                                read_operations = ['GetObject', 'HeadObject', 'ListObjects', 'GetObjectVersion']
                                if any(op in equals for op in read_operations):
                                    has_read_events = True
                    
                    if has_s3_resource and (not field_selectors or has_read_events or 
                                          not any(fs.get('Field') == 'readOnly' for fs in field_selectors)):
                        has_s3_read_events = True
                        s3_read_details.append({
                            'type': 'advanced_selector',
                            'field_selectors': field_selectors
                        })
                
                trail_details = {
                    'trail_name': trail_name,
                    'trail_arn': trail_arn,
                    'has_s3_read_events': has_s3_read_events,
                    's3_read_configuration': s3_read_details,
                    'event_selectors_count': len(event_selectors),
                    'advanced_event_selectors_count': len(advanced_event_selectors)
                }
                
                if has_s3_read_events:
                    compliant_trails.append(trail_details)
                else:
                    non_compliant_trails.append(trail_details)
                    
            except Exception as e:
                logger.warning(f"Could not get event selectors for trail {trail_name}: {e}")
                non_compliant_trails.append({
                    'trail_name': trail_name,
                    'trail_arn': trail_arn,
                    'error': str(e),
                    'has_s3_read_events': False
                })
        
        # Create findings for each trail
        for trail in compliant_trails:
            findings.append({
                'region': region,
                'profile': profile,
                'resource_type': 'CloudTrail',
                'resource_id': trail['trail_name'],
                'status': 'COMPLIANT',
                'compliance_status': 'PASS',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                'recommendation': 'S3 read data events are properly configured for GDPR compliance',
                'details': trail
            })
        
        for trail in non_compliant_trails:
            findings.append({
                'region': region,
                'profile': profile,
                'resource_type': 'CloudTrail',
                'resource_id': trail['trail_name'],
                'status': 'NON_COMPLIANT',
                'compliance_status': 'FAIL',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable S3 read data events for this CloudTrail trail to maintain processing records'),
                'details': trail
            })
        
    except Exception as e:
        logger.error(f"Error in cloudtrail_s3_dataevents_read_enabled check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'CloudTrail',
            'resource_id': f's3-read-events-{region}',
            'status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Review and remediate as needed'),
            'error': str(e)
        })
        
    return findings

def cloudtrail_s3_dataevents_read_enabled(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=cloudtrail_s3_dataevents_read_enabled_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = cloudtrail_s3_dataevents_read_enabled(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

#!/usr/bin/env python3
"""
iso27001_2022_aws - awslambda_function_invoke_api_operations_cloudtrail_logging_enabled

Logs that record activities, exceptions, faults and other relevant events should be produced, stored, protected and analysed.
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
    """Load compliance metadata from compliance_checks.json."""
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
        'function_name': 'awslambda_function_invoke_api_operations_cloudtrail_logging_enabled',
        'id': 'A.12.4.1',
        'name': 'Event logging',
        'description': 'Logs that record activities, exceptions, faults and other relevant events should be produced, stored, protected and analysed.',
        'api_function': 'client = boto3.client(\'cloudtrail\')',
        'user_function': 'lookup_events()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Enable CloudTrail logging for Lambda function invoke API operations'
    }

COMPLIANCE_DATA = load_compliance_metadata('awslambda_function_invoke_api_operations_cloudtrail_logging_enabled')

def awslambda_function_invoke_api_operations_cloudtrail_logging_enabled_check(cloudtrail_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for awslambda_function_invoke_api_operations_cloudtrail_logging_enabled.
    """
    findings = []
    
    try:
        # First, get all CloudTrail trails
        trails_response = cloudtrail_client.describe_trails()
        trails = trails_response.get('trailList', [])
        
        if not trails:
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'CloudTrail',
                'resource_id': f'no-trails-{region}',
                'status': 'NON_COMPLIANT',
                'compliance_status': 'FAIL',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable CloudTrail logging for Lambda function invoke API operations'),
                'details': {
                    'message': 'No CloudTrail trails found - Lambda invoke operations are not being logged',
                    'trail_count': 0
                }
            }
            findings.append(finding)
            return findings
        
        # Check each trail for Lambda invoke logging
        compliant_trails = []
        non_compliant_trails = []
        
        for trail in trails:
            trail_name = trail.get('Name')
            trail_arn = trail.get('TrailARN')
            is_logging = trail.get('IsLogging', False)
            is_multi_region = trail.get('IsMultiRegionTrail', False)
            include_global_service_events = trail.get('IncludeGlobalServiceEvents', False)
            
            # Get trail status
            try:
                trail_status = cloudtrail_client.get_trail_status(Name=trail_name)
                is_logging = trail_status.get('IsLogging', False)
            except Exception as e:
                logger.warning(f"Could not get status for trail {trail_name}: {e}")
            
            # Check if trail has event selectors for Lambda data events
            has_lambda_data_events = False
            try:
                event_selectors = cloudtrail_client.get_event_selectors(TrailName=trail_name)
                selectors = event_selectors.get('EventSelectors', [])
                
                for selector in selectors:
                    data_resources = selector.get('DataResources', [])
                    for resource in data_resources:
                        resource_type = resource.get('Type', '')
                        resource_values = resource.get('Values', [])
                        
                        # Check for Lambda function data events
                        if resource_type == 'AWS::Lambda::Function':
                            if any('*' in value or 'arn:aws:lambda' in value for value in resource_values):
                                has_lambda_data_events = True
                                break
                    
                    if has_lambda_data_events:
                        break
                
                # Also check advanced event selectors (newer CloudTrail feature)
                if not has_lambda_data_events:
                    try:
                        advanced_selectors = cloudtrail_client.get_event_selectors(TrailName=trail_name)
                        adv_selectors = advanced_selectors.get('AdvancedEventSelectors', [])
                        
                        for selector in adv_selectors:
                            field_selectors = selector.get('FieldSelectors', [])
                            for field in field_selectors:
                                if (field.get('Field') == 'eventCategory' and 
                                    'Data' in field.get('Equals', [])):
                                    # Check for Lambda resources in other field selectors
                                    for other_field in field_selectors:
                                        if (other_field.get('Field') == 'resources.type' and
                                            'AWS::Lambda::Function' in other_field.get('Equals', [])):
                                            has_lambda_data_events = True
                                            break
                                if has_lambda_data_events:
                                    break
                            if has_lambda_data_events:
                                break
                    except Exception as e:
                        logger.debug(f"Advanced event selectors not available or error: {e}")
            
            except Exception as e:
                logger.warning(f"Could not get event selectors for trail {trail_name}: {e}")
            
            # Determine compliance status
            if is_logging and has_lambda_data_events:
                compliant_trails.append(trail_name)
                status = 'COMPLIANT'
                compliance_status = 'PASS'
                message = f'CloudTrail {trail_name} is logging Lambda invoke operations'
            else:
                non_compliant_trails.append(trail_name)
                status = 'NON_COMPLIANT'
                compliance_status = 'FAIL'
                
                if not is_logging:
                    message = f'CloudTrail {trail_name} is not actively logging'
                elif not has_lambda_data_events:
                    message = f'CloudTrail {trail_name} is not configured to log Lambda data events'
                else:
                    message = f'CloudTrail {trail_name} configuration issue'
            
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'CloudTrail',
                'resource_id': trail_arn or trail_name,
                'status': status,
                'compliance_status': compliance_status,
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable CloudTrail logging for Lambda function invoke API operations'),
                'details': {
                    'trail_name': trail_name,
                    'trail_arn': trail_arn,
                    'is_logging': is_logging,
                    'is_multi_region': is_multi_region,
                    'include_global_service_events': include_global_service_events,
                    'has_lambda_data_events': has_lambda_data_events,
                    'lambda_invoke_logging_enabled': is_logging and has_lambda_data_events,
                    'message': message
                }
            }
            findings.append(finding)
        
        # If no compliant trails found, add a summary finding
        if not compliant_trails:
            summary_finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'CloudTrail Summary',
                'resource_id': f'lambda-logging-{region}',
                'status': 'NON_COMPLIANT',
                'compliance_status': 'FAIL',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable CloudTrail logging for Lambda function invoke API operations'),
                'details': {
                    'message': 'No CloudTrail trails are properly configured to log Lambda invoke operations',
                    'total_trails': len(trails),
                    'compliant_trails': compliant_trails,
                    'non_compliant_trails': non_compliant_trails
                }
            }
            findings.append(summary_finding)
        
    except Exception as e:
        logger.error(f"Error in awslambda_function_invoke_api_operations_cloudtrail_logging_enabled check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'CloudTrail',
            'resource_id': f'error-{region}',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable CloudTrail logging for Lambda function invoke API operations'),
            'error': str(e)
        })
        
    return findings

def awslambda_function_invoke_api_operations_cloudtrail_logging_enabled(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=awslambda_function_invoke_api_operations_cloudtrail_logging_enabled_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    args = setup_command_line_interface(COMPLIANCE_DATA)
    results = awslambda_function_invoke_api_operations_cloudtrail_logging_enabled(
        profile_name=args.profile,
        region_name=args.region
    )
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

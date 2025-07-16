#!/usr/bin/env python3
"""
ens_rd2022_aws - cloudtrail_insights_exist

Revisión de los registros
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
        'compliance_name': 'ens_rd2022_aws',
        'function_name': 'cloudtrail_insights_exist',
        'id': 'CT.5',
        'name': 'CloudTrail insights should be enabled',
        'description': 'Revisión de los registros',
        'api_function': 'client = boto3.client("cloudtrail")',
        'user_function': 'describe_trails(), get_insight_selectors()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Enable CloudTrail insights to detect unusual activity patterns in AWS API usage'
    }

COMPLIANCE_DATA = load_compliance_metadata('cloudtrail_insights_exist')

def cloudtrail_insights_exist_check(cloudtrail_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for cloudtrail_insights_exist.
    """
    findings = []
    
    try:
        # Get all CloudTrail trails
        response = cloudtrail_client.describe_trails()
        trails = response.get('trailList', [])
        
        for trail in trails:
            trail_name = trail.get('Name')
            trail_arn = trail.get('TrailARN')
            is_multi_region = trail.get('IsMultiRegionTrail', False)
            trail_status = trail.get('LoggingEnabled', False)
            
            # Skip if trail is not logging
            if not trail_status:
                continue
            
            try:
                # Check insight selectors for this trail
                insight_response = cloudtrail_client.get_insight_selectors(TrailName=trail_name)
                insight_selectors = insight_response.get('InsightSelectors', [])
                
                # Check if insights are enabled
                has_insights = len(insight_selectors) > 0
                enabled_insight_types = []
                
                for selector in insight_selectors:
                    insight_type = selector.get('InsightType')
                    if insight_type:
                        enabled_insight_types.append(insight_type)
                
                status = 'COMPLIANT' if has_insights else 'NON_COMPLIANT'
                compliance_status = 'PASS' if has_insights else 'FAIL'
                
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'CLOUDTRAIL_TRAIL',
                    'resource_id': trail_name,
                    'status': status,
                    'compliance_status': compliance_status,
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable CloudTrail insights to detect unusual activity patterns in AWS API usage'),
                    'details': {
                        'trail_name': trail_name,
                        'trail_arn': trail_arn,
                        'is_multi_region': is_multi_region,
                        'logging_enabled': trail_status,
                        'has_insights': has_insights,
                        'insights_count': len(insight_selectors),
                        'enabled_insight_types': enabled_insight_types,
                        'home_region': trail.get('HomeRegion'),
                        'include_global_service_events': trail.get('IncludeGlobalServiceEvents', False)
                    }
                }
                
            except Exception as insight_error:
                logger.warning(f"Could not check insights for trail {trail_name}: {insight_error}")
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'CLOUDTRAIL_TRAIL',
                    'resource_id': trail_name,
                    'status': 'ERROR',
                    'compliance_status': 'ERROR',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable CloudTrail insights to detect unusual activity patterns in AWS API usage'),
                    'details': {
                        'trail_name': trail_name,
                        'trail_arn': trail_arn,
                        'error': str(insight_error),
                        'reason': 'Could not retrieve insight selectors'
                    }
                }
                
            findings.append(finding)
        
        # If no trails found, add informational finding
        if not trails:
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'CLOUDTRAIL_TRAIL',
                'resource_id': 'NO_TRAILS',
                'status': 'NON_COMPLIANT',
                'compliance_status': 'FAIL',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                'recommendation': 'Create CloudTrail trails and enable insights for monitoring',
                'details': {
                    'message': 'No CloudTrail trails found',
                    'trails_count': 0
                }
            }
            findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in cloudtrail_insights_exist check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'CLOUDTRAIL_TRAIL',
            'status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable CloudTrail insights to detect unusual activity patterns in AWS API usage'),
            'error': str(e)
        })
        
    return findings

def cloudtrail_insights_exist(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=cloudtrail_insights_exist_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    args = setup_command_line_interface(COMPLIANCE_DATA)
    results = cloudtrail_insights_exist(
        profile_name=args.profile,
        region_name=args.region
    )
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

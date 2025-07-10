#!/usr/bin/env python3
"""
cis_4.0_aws - cloudtrail_multi_region_enabled

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
        'compliance_name': 'cis_4.0_aws',
        'function_name': 'cloudtrail_multi_region_enabled',
        'id': '3.1',
        'name': 'Ensure CloudTrail is enabled in all regions',
        'description': 'Ensure CloudTrail is enabled in all regions',
        'api_function': 'client = boto3.client("cloudtrail")',
        'user_function': 'describe_trails()',
        'risk_level': 'HIGH',
        'recommendation': 'Enable CloudTrail multi-region logging to ensure comprehensive audit coverage'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('cloudtrail_multi_region_enabled')

def cloudtrail_multi_region_enabled_check(cloudtrail_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for cloudtrail_multi_region_enabled.
    
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
        logger.info(f"Checking CloudTrail multi-region configuration in region {region}")
        
        # Get all CloudTrail trails
        trails_response = cloudtrail_client.describe_trails()
        trails = trails_response.get('trailList', [])
        
        if not trails:
            # No trails found - this is a compliance failure
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'CloudTrail',
                'resource_id': 'no-trails-found',
                'status': 'NON_COMPLIANT',
                'compliance_status': 'FAIL',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                'recommendation': COMPLIANCE_DATA.get('recommendation', 'Create CloudTrail with multi-region logging enabled'),
                'details': {
                    'issue': 'No CloudTrail trails found in account',
                    'trails_count': 0,
                    'security_risk': 'Without CloudTrail, API calls and account activity are not being logged',
                    'remediation_steps': [
                        'Create a new CloudTrail trail',
                        'Enable multi-region logging',
                        'Configure S3 bucket for log storage',
                        'Enable log file validation'
                    ]
                }
            }
            findings.append(finding)
            return findings
        
        # Check for trails with multi-region logging enabled
        multi_region_trails = []
        single_region_trails = []
        
        for trail in trails:
            trail_name = trail.get('Name', 'unknown')
            trail_arn = trail.get('TrailARN', 'unknown')
            is_multi_region = trail.get('IsMultiRegionTrail', False)
            is_logging = trail.get('IsLogging', False)
            
            try:
                # Get additional trail details including status
                trail_status = cloudtrail_client.get_trail_status(Name=trail_name)
                is_logging = trail_status.get('IsLogging', False)
                
                trail_details = {
                    'trail_name': trail_name,
                    'trail_arn': trail_arn,
                    'is_multi_region': is_multi_region,
                    'is_logging': is_logging,
                    's3_bucket_name': trail.get('S3BucketName', 'unknown'),
                    's3_key_prefix': trail.get('S3KeyPrefix', ''),
                    'include_global_service_events': trail.get('IncludeGlobalServiceEvents', False),
                    'log_file_validation_enabled': trail.get('LogFileValidationEnabled', False),
                    'home_region': trail.get('HomeRegion', 'unknown')
                }
                
                if is_multi_region and is_logging:
                    multi_region_trails.append(trail_details)
                else:
                    single_region_trails.append(trail_details)
                    
            except Exception as e:
                logger.warning(f"Could not get status for trail {trail_name}: {e}")
                # Still include the trail in analysis with basic info
                trail_details = {
                    'trail_name': trail_name,
                    'trail_arn': trail_arn,
                    'is_multi_region': is_multi_region,
                    'is_logging': False,  # Assume not logging if we can't check
                    'status_check_error': str(e)
                }
                single_region_trails.append(trail_details)
        
        # Determine compliance status
        if multi_region_trails:
            # Compliant: At least one multi-region trail is active
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'CloudTrail',
                'resource_id': f"multi-region-trails-{len(multi_region_trails)}",
                'status': 'COMPLIANT',
                'compliance_status': 'PASS',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                'recommendation': COMPLIANCE_DATA.get('recommendation', 'CloudTrail multi-region logging is properly configured'),
                'details': {
                    'total_trails': len(trails),
                    'multi_region_trails_count': len(multi_region_trails),
                    'single_region_trails_count': len(single_region_trails),
                    'multi_region_trails': multi_region_trails,
                    'single_region_trails': single_region_trails
                }
            }
        else:
            # Non-compliant: No multi-region trails found
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'CloudTrail',
                'resource_id': f"trails-{len(trails)}",
                'status': 'NON_COMPLIANT',
                'compliance_status': 'FAIL',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable multi-region logging on CloudTrail'),
                'details': {
                    'issue': 'No CloudTrail trails with multi-region logging enabled',
                    'total_trails': len(trails),
                    'multi_region_trails_count': 0,
                    'single_region_trails_count': len(single_region_trails),
                    'single_region_trails': single_region_trails,
                    'security_risk': 'API calls in some regions may not be logged',
                    'remediation_steps': [
                        'Enable multi-region logging on existing trail',
                        'Or create new trail with multi-region logging',
                        'Ensure trail is actively logging',
                        'Verify global service events are included'
                    ]
                }
            }
        
        findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in cloudtrail_multi_region_enabled check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'CloudTrail',
            'status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Review and remediate as needed'),
            'error': str(e)
        })
        
    return findings

def cloudtrail_multi_region_enabled(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=cloudtrail_multi_region_enabled_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = cloudtrail_multi_region_enabled(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

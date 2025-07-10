#!/usr/bin/env python3
"""
kisa_isms_p_2023_aws - iam_user_with_temporary_credentials

User access to information systems, personal information, and critical information must be secured through safe authentication procedures and, if necessary, enhanced authentication methods. In addition, access control measures such as limiting login attempts and issuing warnings for illegal login attempts must be established and implemented.
"""

import sys
import os
import json
from typing import Dict, List, Any
from datetime import datetime, timedelta

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
                    'recommendation': entry.get('Recommendation', 'Ensure users use temporary credentials instead of permanent access keys')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'kisa_isms_p_2023_aws',
        'function_name': 'iam_user_with_temporary_credentials',
        'id': '2.5.3',
        'name': 'User Authentication',
        'description': 'User access to information systems, personal information, and critical information must be secured through safe authentication procedures and, if necessary, enhanced authentication methods.',
        'api_function': 'client=boto3.client(\'cloudtrail\')',
        'user_function': 'lookup_events()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Ensure users use temporary credentials instead of permanent access keys'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('iam_user_with_temporary_credentials')

def iam_user_with_temporary_credentials_check(cloudtrail_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for iam_user_with_temporary_credentials.
    
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
        # Look for STS assume role events (temporary credentials usage)
        logger.info("Checking for temporary credentials usage via STS events...")
        
        # Look for events in the last 30 days
        start_time = datetime.utcnow() - timedelta(days=30)
        end_time = datetime.utcnow()
        
        # Search for STS AssumeRole events (temporary credentials)
        sts_events = cloudtrail_client.lookup_events(
            LookupAttributes=[
                {
                    'AttributeKey': 'EventName',
                    'AttributeValue': 'AssumeRole'
                }
            ],
            StartTime=start_time,
            EndTime=end_time
        )
        
        # Search for access key usage events (permanent credentials)
        access_key_events = cloudtrail_client.lookup_events(
            LookupAttributes=[
                {
                    'AttributeKey': 'UserName', 
                    'AttributeValue': 'IAMUser'
                }
            ],
            StartTime=start_time,
            EndTime=end_time
        )
        
        # Count events
        temp_credential_events = len(sts_events.get('Events', []))
        permanent_credential_events = len(access_key_events.get('Events', []))
        
        # Analyze credential usage patterns
        if temp_credential_events > 0 or permanent_credential_events > 0:
            # Calculate ratio of temporary vs permanent credential usage
            total_events = temp_credential_events + permanent_credential_events
            temp_ratio = temp_credential_events / total_events if total_events > 0 else 0
            
            # Compliance threshold: prefer >70% temporary credential usage
            if temp_ratio >= 0.7:
                status = 'COMPLIANT'
                compliance_status = 'PASS'
                message = f"Good use of temporary credentials: {temp_credential_events} temporary vs {permanent_credential_events} permanent events"
            elif temp_ratio >= 0.3:
                status = 'NON_COMPLIANT'
                compliance_status = 'FAIL'
                message = f"Mixed credential usage: {temp_credential_events} temporary vs {permanent_credential_events} permanent events"
            else:
                status = 'NON_COMPLIANT'
                compliance_status = 'FAIL'
                message = f"Heavy reliance on permanent credentials: {temp_credential_events} temporary vs {permanent_credential_events} permanent events"
                
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'CloudTrail Credential Usage',
                'resource_id': f"{region}-credential-analysis",
                'status': status,
                'compliance_status': compliance_status,
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                'recommendation': COMPLIANCE_DATA.get('recommendation', 'Ensure users use temporary credentials instead of permanent access keys'),
                'details': {
                    'temporary_credential_events': temp_credential_events,
                    'permanent_credential_events': permanent_credential_events,
                    'temporary_credential_ratio': round(temp_ratio * 100, 2),
                    'analysis_period_days': 30,
                    'message': message
                }
            }
            
        else:
            # No credential usage detected
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'CloudTrail Credential Usage',
                'resource_id': f"{region}-credential-analysis",
                'status': 'COMPLIANT',
                'compliance_status': 'PASS',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                'recommendation': COMPLIANCE_DATA.get('recommendation', 'Ensure users use temporary credentials instead of permanent access keys'),
                'details': {
                    'temporary_credential_events': 0,
                    'permanent_credential_events': 0,
                    'temporary_credential_ratio': 0,
                    'analysis_period_days': 30,
                    'message': 'No credential usage events detected in the analysis period'
                }
            }
            
        findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in iam_user_with_temporary_credentials check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'CloudTrail Credential Usage',
            'resource_id': 'Unknown',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Ensure users use temporary credentials instead of permanent access keys'),
            'error': str(e),
            'details': {
                'error_message': str(e),
                'check_type': 'iam_user_with_temporary_credentials'
            }
        })
        
    return findings

def iam_user_with_temporary_credentials(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=iam_user_with_temporary_credentials_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = iam_user_with_temporary_credentials(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

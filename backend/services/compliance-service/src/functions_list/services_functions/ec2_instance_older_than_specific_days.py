#!/usr/bin/env python3
"""
iso27001_2022_aws - ec2_instance_older_than_specific_days

Information systems should be regularly reviewed to ensure they continue to operate effectively and securely.
"""

import sys
import os
import json
from datetime import datetime, timezone, timedelta
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
                    'recommendation': entry.get('Recommendation', 'Review and update instances older than recommended lifecycle period')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    return {
        'compliance_name': 'iso27001_2022_aws',
        'function_name': 'ec2_instance_older_than_specific_days',
        'id': 'ISO-27001-2022-A.12.6',
        'name': 'Systems Lifecycle Management',
        'description': 'Information systems should be regularly reviewed to ensure they continue to operate effectively and securely.',
        'api_function': 'client = boto3.client(\'ec2\')',
        'user_function': 'describe_instances()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Review and update instances older than recommended lifecycle period'
    }

COMPLIANCE_DATA = load_compliance_metadata('ec2_instance_older_than_specific_days')

def calculate_instance_age(launch_time: datetime, threshold_days: int = 365) -> Dict[str, Any]:
    """Calculate the age of an EC2 instance and determine if it exceeds the threshold."""
    current_time = datetime.now(timezone.utc)
    
    # Ensure launch_time is timezone aware
    if launch_time.tzinfo is None:
        launch_time = launch_time.replace(tzinfo=timezone.utc)
    
    age_delta = current_time - launch_time
    age_days = age_delta.days
    age_hours = age_delta.seconds // 3600
    
    is_older_than_threshold = age_days > threshold_days
    
    return {
        'age_days': age_days,
        'age_hours': age_hours,
        'is_older_than_threshold': is_older_than_threshold,
        'threshold_days': threshold_days,
        'launch_time_iso': launch_time.isoformat(),
        'current_time_iso': current_time.isoformat(),
        'age_category': get_age_category(age_days)
    }

def get_age_category(age_days: int) -> str:
    """Categorize instance age for better reporting."""
    if age_days <= 30:
        return 'new'
    elif age_days <= 180:
        return 'recent'
    elif age_days <= 365:
        return 'mature'
    elif age_days <= 730:
        return 'aged'
    else:
        return 'legacy'

def ec2_instance_older_than_specific_days_check(ec2_client, region: str, profile: str, logger, threshold_days: int = 365) -> List[Dict[str, Any]]:
    """Perform the actual compliance check for ec2_instance_older_than_specific_days."""
    findings = []
    
    try:
        # Get all EC2 instances
        response = ec2_client.describe_instances()
        reservations = response.get('Reservations', [])
        
        all_instances = []
        for reservation in reservations:
            all_instances.extend(reservation.get('Instances', []))
        
        if not all_instances:
            finding = {
                'region': region, 'profile': profile, 'resource_type': 'EC2Instance',
                'resource_id': f'no-ec2-instances-{region}', 'status': 'COMPLIANT',
                'compliance_status': 'PASS', 'risk_level': 'LOW',
                'recommendation': 'No EC2 instances found in this region',
                'details': {'instances_count': 0, 'message': 'No EC2 instances found to check for age compliance'}
            }
            findings.append(finding)
            return findings
        
        # Check each instance
        old_instances_count = 0
        instances_checked = 0
        
        for instance in all_instances:
            instance_id = instance.get('InstanceId', 'unknown')
            instance_state = instance.get('State', {}).get('Name', 'unknown')
            instance_type = instance.get('InstanceType', 'unknown')
            launch_time = instance.get('LaunchTime')
            
            # Skip terminated instances
            if instance_state in ['terminated', 'shutting-down']:
                continue
            
            instances_checked += 1
            
            if not launch_time:
                # Instance without launch time - treat as non-compliant
                status = 'NON_COMPLIANT'
                compliance_status = 'FAIL'
                risk_level = COMPLIANCE_DATA.get('risk_level', 'MEDIUM')
                recommendation = 'Instance launch time not available - manual review required'
                age_analysis = {
                    'age_days': 'unknown',
                    'age_hours': 'unknown',
                    'is_older_than_threshold': True,
                    'threshold_days': threshold_days,
                    'launch_time_iso': None,
                    'age_category': 'unknown'
                }
            else:
                # Calculate instance age
                age_analysis = calculate_instance_age(launch_time, threshold_days)
                
                if age_analysis['is_older_than_threshold']:
                    old_instances_count += 1
                    status = 'NON_COMPLIANT'
                    compliance_status = 'FAIL'
                    risk_level = COMPLIANCE_DATA.get('risk_level', 'MEDIUM')
                    recommendation = COMPLIANCE_DATA.get('recommendation', 'Review and update old instances')
                else:
                    status = 'COMPLIANT'
                    compliance_status = 'PASS'
                    risk_level = 'LOW'
                    recommendation = 'Instance age is within acceptable limits'
            
            # Get instance tags for additional context
            tags = {tag.get('Key', ''): tag.get('Value', '') for tag in instance.get('Tags', [])}
            
            finding = {
                'region': region, 'profile': profile, 'resource_type': 'EC2Instance',
                'resource_id': instance_id, 'status': status, 'compliance_status': compliance_status,
                'risk_level': risk_level, 'recommendation': recommendation,
                'details': {
                    'instance_id': instance_id, 'instance_state': instance_state, 'instance_type': instance_type,
                    'age_days': age_analysis['age_days'], 'age_category': age_analysis['age_category'],
                    'is_older_than_threshold': age_analysis['is_older_than_threshold'],
                    'threshold_days': age_analysis['threshold_days'],
                    'launch_time': age_analysis.get('launch_time_iso'),
                    'platform': instance.get('Platform', 'linux'),
                    'availability_zone': instance.get('Placement', {}).get('AvailabilityZone', 'unknown'),
                    'vpc_id': instance.get('VpcId', 'unknown'),
                    'subnet_id': instance.get('SubnetId', 'unknown'),
                    'tags': tags,
                    'security_note': 'Older instances may lack security patches and modern configurations',
                    'lifecycle_note': 'Regular instance refresh helps maintain security and performance standards'
                }
            }
            findings.append(finding)
        
        logger.info(f"Checked {instances_checked} active EC2 instances, found {old_instances_count} older than {threshold_days} days")
        
    except Exception as e:
        logger.error(f"Error in ec2_instance_older_than_specific_days check for {region}: {e}")
        findings.append({
            'region': region, 'profile': profile, 'resource_type': 'EC2Instance',
            'resource_id': f'error-check-{region}', 'status': 'ERROR', 'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Review and update old instances'),
            'error': str(e)
        })
        
    return findings

def ec2_instance_older_than_specific_days(profile_name: str = None, region_name: str = None, threshold_days: int = 365) -> Dict[str, Any]:
    """
    Main compliance check function.
    
    Args:
        profile_name: AWS profile name
        region_name: AWS region name
        threshold_days: Age threshold in days (default 365)
    """
    engine = ComplianceEngine(COMPLIANCE_DATA)
    
    # Create a custom check function with the threshold
    def custom_check(ec2_client, region, profile, logger):
        return ec2_instance_older_than_specific_days_check(ec2_client, region, profile, logger, threshold_days)
    
    return engine.run_compliance_check(
        check_function=custom_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Allow threshold to be passed as environment variable
    threshold = int(os.environ.get('EC2_AGE_THRESHOLD_DAYS', 365))
    
    results = ec2_instance_older_than_specific_days(
        profile_name=args.profile, region_name=args.region, threshold_days=threshold
    )
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

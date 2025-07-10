#!/usr/bin/env python3
"""
pci_3.2.1_aws - ec2_instance_profile_attached

Systems components that store, process, or transmit cardholder data (CHD) and/or sensitive authentication data (SAD), and/or could impact the security of the cardholder data environment (CDE) must be included in the scope of the PCI DSS assessment.
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
                    'recommendation': entry.get('Recommendation', 'Attach IAM instance profiles to EC2 instances for secure API access without hardcoded credentials')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'pci_3.2.1_aws',
        'function_name': 'ec2_instance_profile_attached',
        'id': 'PCI-DSS-3.2.1-2.4',
        'name': 'Instance Profile Management',
        'description': 'Systems components that store, process, or transmit cardholder data (CHD) and/or sensitive authentication data (SAD), and/or could impact the security of the cardholder data environment (CDE) must be included in the scope of the PCI DSS assessment.',
        'api_function': 'client=boto3.client(\'ec2\')',
        'user_function': 'describe_instances()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Attach IAM instance profiles to EC2 instances for secure API access without hardcoded credentials'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('ec2_instance_profile_attached')

def analyze_instance_profile(instance: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyze EC2 instance for IAM instance profile attachment.
    
    Args:
        instance: EC2 instance configuration
        
    Returns:
        Analysis results with instance profile details
    """
    analysis = {
        'has_instance_profile': False,
        'instance_profile_arn': None,
        'instance_profile_name': None,
        'iam_role_arn': None,
        'iam_role_name': None,
        'requires_aws_access': True  # Assume instances need AWS API access unless specified
    }
    
    # Check for IAM instance profile
    iam_instance_profile = instance.get('IamInstanceProfile', {})
    
    if iam_instance_profile:
        analysis['has_instance_profile'] = True
        analysis['instance_profile_arn'] = iam_instance_profile.get('Arn')
        
        # Extract instance profile name from ARN
        arn = iam_instance_profile.get('Arn', '')
        if arn:
            # ARN format: arn:aws:iam::account-id:instance-profile/name
            analysis['instance_profile_name'] = arn.split('/')[-1] if '/' in arn else arn
        
        # Note: The IAM role associated with instance profile would need separate IAM API call
        # For this compliance check, we focus on presence of instance profile
    
    return analysis

def assess_instance_aws_access_need(instance: Dict[str, Any], logger) -> bool:
    """
    Assess if an EC2 instance likely needs AWS API access based on its configuration.
    
    Args:
        instance: EC2 instance configuration
        logger: Logger instance
        
    Returns:
        True if instance likely needs AWS access, False otherwise
    """
    # Check instance tags for clues about purpose
    tags = {tag.get('Key', ''): tag.get('Value', '') for tag in instance.get('Tags', [])}
    
    # Common patterns that suggest AWS API access is needed
    aws_service_indicators = [
        'backup', 'monitoring', 'logging', 'cloudwatch', 'lambda', 'sns', 'sqs',
        'rds', 's3', 'dynamodb', 'secretsmanager', 'ssm', 'autoscaling'
    ]
    
    # Check tags for AWS service indicators
    for tag_key, tag_value in tags.items():
        combined_text = f"{tag_key} {tag_value}".lower()
        for indicator in aws_service_indicators:
            if indicator in combined_text:
                return True
    
    # Check instance type - certain types commonly used for AWS workloads
    instance_type = instance.get('InstanceType', '')
    if any(pattern in instance_type for pattern in ['t3.', 't4g.', 'm5.', 'm6i.', 'c5.', 'c6i.']):
        # These are commonly used for applications that integrate with AWS services
        return True
    
    # Check if instance is in a VPC (most modern workloads are)
    vpc_id = instance.get('VpcId')
    if vpc_id and vpc_id != 'vpc-':  # Not in EC2-Classic
        return True
    
    # If we can't determine, assume it needs AWS access for security
    return True

def ec2_instance_profile_attached_check(ec2_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for ec2_instance_profile_attached.
    
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
        # Get all EC2 instances
        response = ec2_client.describe_instances()
        reservations = response.get('Reservations', [])
        
        all_instances = []
        for reservation in reservations:
            all_instances.extend(reservation.get('Instances', []))
        
        if not all_instances:
            # No EC2 instances found
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'EC2Instance',
                'resource_id': f'no-ec2-instances-{region}',
                'status': 'COMPLIANT',
                'compliance_status': 'PASS',
                'risk_level': 'LOW',
                'recommendation': 'No EC2 instances found in this region',
                'details': {
                    'instances_count': 0,
                    'message': 'No EC2 instances found to check for instance profile attachment'
                }
            }
            findings.append(finding)
            return findings
        
        # Check each instance for instance profile attachment
        instances_without_profile = 0
        instances_checked = 0
        
        for instance in all_instances:
            instance_id = instance.get('InstanceId', 'unknown')
            instance_state = instance.get('State', {}).get('Name', 'unknown')
            instance_type = instance.get('InstanceType', 'unknown')
            
            # Skip terminated instances
            if instance_state in ['terminated', 'shutting-down']:
                continue
            
            instances_checked += 1
            
            # Analyze instance profile attachment
            profile_analysis = analyze_instance_profile(instance)
            
            # Assess if instance needs AWS access
            needs_aws_access = assess_instance_aws_access_need(instance, logger)
            
            # Determine compliance status
            has_profile = profile_analysis['has_instance_profile']
            
            if not has_profile and needs_aws_access:
                instances_without_profile += 1
                status = 'NON_COMPLIANT'
                compliance_status = 'FAIL'
                risk_level = COMPLIANCE_DATA.get('risk_level', 'MEDIUM')
                recommendation = COMPLIANCE_DATA.get('recommendation', 'Attach IAM instance profile to EC2 instance')
            elif not has_profile and not needs_aws_access:
                status = 'COMPLIANT'
                compliance_status = 'PASS'
                risk_level = 'LOW'
                recommendation = 'Instance appears to not require AWS API access, no instance profile needed'
            else:
                status = 'COMPLIANT'
                compliance_status = 'PASS'
                risk_level = 'LOW'
                recommendation = 'EC2 instance has IAM instance profile properly attached'
            
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'EC2Instance',
                'resource_id': instance_id,
                'status': status,
                'compliance_status': compliance_status,
                'risk_level': risk_level,
                'recommendation': recommendation,
                'details': {
                    'instance_id': instance_id,
                    'instance_state': instance_state,
                    'instance_type': instance_type,
                    'has_instance_profile': has_profile,
                    'instance_profile_arn': profile_analysis['instance_profile_arn'],
                    'instance_profile_name': profile_analysis['instance_profile_name'],
                    'assessed_needs_aws_access': needs_aws_access,
                    'availability_zone': instance.get('Placement', {}).get('AvailabilityZone', 'unknown'),
                    'vpc_id': instance.get('VpcId', 'unknown'),
                    'subnet_id': instance.get('SubnetId', 'unknown'),
                    'launch_time': instance.get('LaunchTime', '').isoformat() if instance.get('LaunchTime') else None,
                    'public_ip_address': instance.get('PublicIpAddress'),
                    'private_ip_address': instance.get('PrivateIpAddress'),
                    'security_groups': [sg.get('GroupId', '') for sg in instance.get('SecurityGroups', [])],
                    'tags': instance.get('Tags', []),
                    'platform': instance.get('Platform', 'linux'),
                    'security_note': 'Instance profiles provide secure access to AWS APIs without hardcoded credentials'
                }
            }
            
            findings.append(finding)
        
        logger.info(f"Checked {instances_checked} active EC2 instances, found {instances_without_profile} without instance profiles that may need AWS access")
        
    except Exception as e:
        logger.error(f"Error in ec2_instance_profile_attached check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'EC2Instance',
            'resource_id': f'error-check-{region}',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Attach IAM instance profiles to EC2 instances'),
            'error': str(e)
        })
        
    return findings

def ec2_instance_profile_attached(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=ec2_instance_profile_attached_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = ec2_instance_profile_attached(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

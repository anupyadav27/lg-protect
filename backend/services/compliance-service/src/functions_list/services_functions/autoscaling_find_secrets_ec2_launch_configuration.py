#!/usr/bin/env python3
"""
aws_well_architected_framework_security_pillar_aws - autoscaling_find_secrets_ec2_launch_configuration

A workload requires an automated capability to prove its identity to databases, resources, and third-party services. This is accomplished using secret access credentials, such as API access keys, passwords, and OAuth tokens. Using a purpose-built service to store, manage, and rotate these credentials helps reduce the likelihood that those credentials become compromised.
"""

import sys
import os
import json
import re
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
                    'risk_level': entry.get('Risk Level', 'HIGH'),
                    'recommendation': entry.get('Recommendation', 'Remove hardcoded secrets from launch configurations and use AWS Secrets Manager or Parameter Store')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'aws_well_architected_framework_security_pillar_aws',
        'function_name': 'autoscaling_find_secrets_ec2_launch_configuration',
        'id': 'WAF-SEC-SECRET-MGMT',
        'name': 'AutoScaling Launch Configuration Secret Detection',
        'description': 'A workload requires an automated capability to prove its identity to databases, resources, and third-party services. This is accomplished using secret access credentials, such as API access keys, passwords, and OAuth tokens. Using a purpose-built service to store, manage, and rotate these credentials helps reduce the likelihood that those credentials become compromised.',
        'api_function': 'client = boto3.client(\'autoscaling\')',
        'user_function': 'describe_auto_scaling_groups(), describe_launch_configurations()',
        'risk_level': 'HIGH',
        'recommendation': 'Remove hardcoded secrets from launch configurations and use AWS Secrets Manager or Parameter Store'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('autoscaling_find_secrets_ec2_launch_configuration')

def detect_secrets_in_text(text: str) -> List[Dict[str, str]]:
    """Detect potential secrets in text using regex patterns."""
    secrets_found = []
    
    # Common secret patterns
    secret_patterns = {
        'AWS Access Key ID': r'AKIA[0-9A-Z]{16}',
        'AWS Secret Access Key': r'[A-Za-z0-9/+=]{40}',
        'Generic API Key': r'(?i)(api[_-]?key|apikey)\s*[:=]\s*[\'"]?([a-zA-Z0-9]{16,})[\'"]?',
        'Password': r'(?i)(password|pwd|pass)\s*[:=]\s*[\'"]?([^\s\'"]+)[\'"]?',
        'Database Connection String': r'(?i)(connection[_-]?string|conn[_-]?str)\s*[:=]\s*[\'"]?([^\s\'"]+)[\'"]?',
        'Private Key': r'-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----',
        'Generic Secret': r'(?i)(secret|token|credential)\s*[:=]\s*[\'"]?([a-zA-Z0-9]{16,})[\'"]?',
        'Database Password': r'(?i)(db[_-]?password|database[_-]?password)\s*[:=]\s*[\'"]?([^\s\'"]+)[\'"]?'
    }
    
    for secret_type, pattern in secret_patterns.items():
        matches = re.finditer(pattern, text)
        for match in matches:
            # Don't include obvious placeholders or examples
            matched_text = match.group(0)
            if not any(placeholder in matched_text.lower() 
                      for placeholder in ['example', 'placeholder', 'your_', 'xxx', '***', 'dummy', 'test']):
                secrets_found.append({
                    'type': secret_type,
                    'pattern': pattern,
                    'matched_text': matched_text[:50] + '...' if len(matched_text) > 50 else matched_text,
                    'position': match.start()
                })
    
    return secrets_found

def autoscaling_find_secrets_ec2_launch_configuration_check(autoscaling_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for finding secrets in AutoScaling launch configurations.
    
    Args:
        autoscaling_client: Boto3 AutoScaling client
        region (str): AWS region
        profile (str): AWS profile name
        logger: Logger instance
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    try:
        # Get all Auto Scaling groups
        asg_paginator = autoscaling_client.get_paginator('describe_auto_scaling_groups')
        launch_configs_to_check = set()
        
        for page in asg_paginator.paginate():
            asgs = page.get('AutoScalingGroups', [])
            
            for asg in asgs:
                # Check if ASG uses launch configuration (not launch template)
                launch_config_name = asg.get('LaunchConfigurationName')
                if launch_config_name:
                    launch_configs_to_check.add(launch_config_name)
        
        if not launch_configs_to_check:
            findings.append({
                'region': region,
                'profile': profile,
                'resource_type': 'AutoScalingGroup',
                'resource_id': 'no-launch-configurations',
                'status': 'COMPLIANT',
                'compliance_status': 'PASS',
                'risk_level': 'INFO',
                'recommendation': 'No launch configurations found - ASGs may be using launch templates instead',
                'details': {
                    'message': 'No Auto Scaling Groups using launch configurations found'
                }
            })
            return findings
        
        # Get launch configuration details
        lc_paginator = autoscaling_client.get_paginator('describe_launch_configurations')
        
        for page in lc_paginator.paginate():
            launch_configs = page.get('LaunchConfigurations', [])
            
            for lc in launch_configs:
                lc_name = lc.get('LaunchConfigurationName')
                
                # Only check launch configurations that are actually in use
                if lc_name not in launch_configs_to_check:
                    continue
                
                secrets_found = []
                
                # Check user data for secrets
                user_data = lc.get('UserData', '')
                if user_data:
                    # UserData is base64 encoded, decode it first
                    try:
                        import base64
                        decoded_user_data = base64.b64decode(user_data).decode('utf-8')
                        user_data_secrets = detect_secrets_in_text(decoded_user_data)
                        
                        for secret in user_data_secrets:
                            secret['location'] = 'UserData'
                            secrets_found.append(secret)
                            
                    except Exception as e:
                        logger.warning(f"Could not decode UserData for launch config {lc_name}: {e}")
                
                # Check security groups and other configurations for potential secrets
                # (Though less likely, sometimes people put secrets in names or descriptions)
                security_groups = lc.get('SecurityGroups', [])
                for sg in security_groups:
                    sg_secrets = detect_secrets_in_text(str(sg))
                    for secret in sg_secrets:
                        secret['location'] = 'SecurityGroups'
                        secrets_found.append(secret)
                
                # Check IAM instance profile for embedded secrets (rare but possible)
                iam_instance_profile = lc.get('IamInstanceProfile', '')
                if iam_instance_profile:
                    profile_secrets = detect_secrets_in_text(iam_instance_profile)
                    for secret in profile_secrets:
                        secret['location'] = 'IamInstanceProfile'
                        secrets_found.append(secret)
                
                # Check key name for potential secrets
                key_name = lc.get('KeyName', '')
                if key_name:
                    key_secrets = detect_secrets_in_text(key_name)
                    for secret in key_secrets:
                        secret['location'] = 'KeyName'
                        secrets_found.append(secret)
                
                if secrets_found:
                    # Secrets detected - non-compliant
                    findings.append({
                        'region': region,
                        'profile': profile,
                        'resource_type': 'LaunchConfiguration',
                        'resource_id': lc_name,
                        'status': 'NON_COMPLIANT',
                        'compliance_status': 'FAIL',
                        'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                        'recommendation': COMPLIANCE_DATA.get('recommendation', 'Remove hardcoded secrets from launch configurations and use AWS Secrets Manager or Parameter Store'),
                        'details': {
                            'launch_configuration_name': lc_name,
                            'secrets_detected': len(secrets_found),
                            'secret_types': list(set(secret['type'] for secret in secrets_found)),
                            'secret_locations': list(set(secret['location'] for secret in secrets_found)),
                            'secrets': secrets_found,
                            'image_id': lc.get('ImageId'),
                            'instance_type': lc.get('InstanceType'),
                            'created_time': lc.get('CreatedTime', '').isoformat() if lc.get('CreatedTime') else 'Unknown'
                        }
                    })
                else:
                    # No secrets detected - compliant
                    findings.append({
                        'region': region,
                        'profile': profile,
                        'resource_type': 'LaunchConfiguration',
                        'resource_id': lc_name,
                        'status': 'COMPLIANT',
                        'compliance_status': 'PASS',
                        'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                        'recommendation': 'No hardcoded secrets detected in launch configuration',
                        'details': {
                            'launch_configuration_name': lc_name,
                            'secrets_detected': 0,
                            'image_id': lc.get('ImageId'),
                            'instance_type': lc.get('InstanceType'),
                            'created_time': lc.get('CreatedTime', '').isoformat() if lc.get('CreatedTime') else 'Unknown',
                            'has_user_data': bool(lc.get('UserData')),
                            'security_groups_count': len(lc.get('SecurityGroups', []))
                        }
                    })
        
    except Exception as e:
        logger.error(f"Error in autoscaling_find_secrets_ec2_launch_configuration check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'LaunchConfiguration',
            'resource_id': 'check-error',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Remove hardcoded secrets from launch configurations and use AWS Secrets Manager or Parameter Store'),
            'error': str(e)
        })
        
    return findings

def autoscaling_find_secrets_ec2_launch_configuration(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=autoscaling_find_secrets_ec2_launch_configuration_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = autoscaling_find_secrets_ec2_launch_configuration(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

#!/usr/bin/env python3
"""
iso27001_2022_aws - ec2_instance_secrets_user_data

Security mechanisms, service levels and service requirements of network services should be identified, implemented and monitored.
"""

import sys
import os
import json
import re
import base64
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
        'compliance_name': 'iso27001_2022_aws',
        'function_name': 'ec2_instance_secrets_user_data',
        'id': 'EC2.3',
        'name': 'EC2 instances should not contain secrets in user data',
        'description': 'Security mechanisms, service levels and service requirements of network services should be identified, implemented and monitored.',
        'api_function': 'client = boto3.client("ec2")',
        'user_function': 'describe_instances()',
        'risk_level': 'HIGH',
        'recommendation': 'Remove secrets from EC2 user data and use AWS Systems Manager Parameter Store or AWS Secrets Manager instead'
    }

COMPLIANCE_DATA = load_compliance_metadata('ec2_instance_secrets_user_data')

def detect_secrets_in_text(text: str) -> List[Dict[str, Any]]:
    """
    Detect potential secrets in text using pattern matching.
    
    Returns:
        List of detected secret patterns with their types and positions
    """
    secrets = []
    
    # Define secret patterns
    secret_patterns = {
        'aws_access_key': r'AKIA[0-9A-Z]{16}',
        'aws_secret_key': r'[A-Za-z0-9/+=]{40}',
        'password_keyword': r'(?i)(password|passwd|pwd)\s*[:=]\s*["\']?([^"\'\s]{6,})["\']?',
        'api_key_keyword': r'(?i)(api_key|apikey|api-key)\s*[:=]\s*["\']?([^"\'\s]{10,})["\']?',
        'secret_keyword': r'(?i)(secret|token)\s*[:=]\s*["\']?([^"\'\s]{10,})["\']?',
        'private_key': r'-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----',
        'ssh_key': r'ssh-(rsa|dsa|ed25519)\s+[A-Za-z0-9+/]+=*',
        'generic_secret': r'(?i)(key|token|secret|password)\s*[:=]\s*["\'][^"\']{20,}["\']',
        'base64_encoded': r'[A-Za-z0-9+/]{50,}={0,2}'  # Potential base64 encoded secrets
    }
    
    for secret_type, pattern in secret_patterns.items():
        matches = re.finditer(pattern, text)
        for match in matches:
            # Skip very common/generic patterns that are likely false positives
            matched_text = match.group(0)
            if not is_likely_false_positive(matched_text, secret_type):
                secrets.append({
                    'type': secret_type,
                    'pattern': pattern,
                    'match': matched_text[:50] + '...' if len(matched_text) > 50 else matched_text,
                    'start_pos': match.start(),
                    'end_pos': match.end()
                })
    
    return secrets

def is_likely_false_positive(text: str, secret_type: str) -> bool:
    """Check if the detected pattern is likely a false positive."""
    false_positive_patterns = [
        r'example\.com',
        r'localhost',
        r'127\.0\.0\.1',
        r'placeholder',
        r'dummy',
        r'test',
        r'sample',
        r'xxxxxxxx',
        r'<.*>',
        r'\$\{.*\}',  # Variable substitution
        r'{{.*}}',    # Template variables
    ]
    
    text_lower = text.lower()
    for fp_pattern in false_positive_patterns:
        if re.search(fp_pattern, text_lower):
            return True
    
    # Additional checks for specific secret types
    if secret_type == 'base64_encoded':
        # Skip if it's too short or contains obvious non-secret content
        if len(text) < 50 or any(word in text_lower for word in ['http', 'www', 'com', 'org']):
            return True
    
    return False

def ec2_instance_secrets_user_data_check(ec2_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for ec2_instance_secrets_user_data.
    """
    findings = []
    
    try:
        # Get all EC2 instances
        response = ec2_client.describe_instances()
        reservations = response.get('Reservations', [])
        
        for reservation in reservations:
            instances = reservation.get('Instances', [])
            
            for instance in instances:
                instance_id = instance.get('InstanceId')
                instance_state = instance.get('State', {}).get('Name', 'unknown')
                
                # Skip terminated instances
                if instance_state == 'terminated':
                    continue
                
                try:
                    # Get instance attribute for user data
                    user_data_response = ec2_client.describe_instance_attribute(
                        InstanceId=instance_id,
                        Attribute='userData'
                    )
                    
                    user_data = user_data_response.get('UserData', {})
                    user_data_value = user_data.get('Value', '')
                    
                    # Decode base64 user data if present
                    decoded_user_data = ''
                    has_user_data = bool(user_data_value)
                    
                    if user_data_value:
                        try:
                            decoded_user_data = base64.b64decode(user_data_value).decode('utf-8', errors='ignore')
                        except Exception as decode_error:
                            logger.warning(f"Could not decode user data for instance {instance_id}: {decode_error}")
                            decoded_user_data = user_data_value  # Use raw value if decode fails
                    
                    # Check for secrets in user data
                    detected_secrets = []
                    if decoded_user_data:
                        detected_secrets = detect_secrets_in_text(decoded_user_data)
                    
                    has_secrets = len(detected_secrets) > 0
                    
                    status = 'NON_COMPLIANT' if has_secrets else 'COMPLIANT'
                    compliance_status = 'FAIL' if has_secrets else 'PASS'
                    
                    finding = {
                        'region': region,
                        'profile': profile,
                        'resource_type': 'EC2_INSTANCE',
                        'resource_id': instance_id,
                        'status': status,
                        'compliance_status': compliance_status,
                        'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                        'recommendation': COMPLIANCE_DATA.get('recommendation', 'Remove secrets from EC2 user data and use AWS Systems Manager Parameter Store or AWS Secrets Manager instead'),
                        'details': {
                            'instance_id': instance_id,
                            'instance_state': instance_state,
                            'instance_type': instance.get('InstanceType'),
                            'launch_time': str(instance.get('LaunchTime', '')),
                            'has_user_data': has_user_data,
                            'user_data_length': len(decoded_user_data) if decoded_user_data else 0,
                            'has_secrets': has_secrets,
                            'secrets_count': len(detected_secrets),
                            'detected_secret_types': [s['type'] for s in detected_secrets],
                            'detected_secrets': detected_secrets
                        }
                    }
                    
                except Exception as instance_error:
                    logger.warning(f"Could not check user data for instance {instance_id}: {instance_error}")
                    finding = {
                        'region': region,
                        'profile': profile,
                        'resource_type': 'EC2_INSTANCE',
                        'resource_id': instance_id,
                        'status': 'ERROR',
                        'compliance_status': 'ERROR',
                        'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                        'recommendation': COMPLIANCE_DATA.get('recommendation', 'Remove secrets from EC2 user data and use AWS Systems Manager Parameter Store or AWS Secrets Manager instead'),
                        'details': {
                            'instance_id': instance_id,
                            'instance_state': instance_state,
                            'error': str(instance_error),
                            'reason': 'Could not retrieve user data'
                        }
                    }
                
                findings.append(finding)
        
        # If no instances found, add informational finding
        if not any(reservation.get('Instances', []) for reservation in reservations):
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'EC2_INSTANCE',
                'resource_id': 'NO_INSTANCES',
                'status': 'COMPLIANT',
                'compliance_status': 'PASS',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                'recommendation': 'No EC2 instances found in this region',
                'details': {
                    'message': 'No EC2 instances found',
                    'instances_count': 0
                }
            }
            findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in ec2_instance_secrets_user_data check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'EC2_INSTANCE',
            'status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Remove secrets from EC2 user data and use AWS Systems Manager Parameter Store or AWS Secrets Manager instead'),
            'error': str(e)
        })
        
    return findings

def ec2_instance_secrets_user_data(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=ec2_instance_secrets_user_data_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    args = setup_command_line_interface(COMPLIANCE_DATA)
    results = ec2_instance_secrets_user_data(
        profile_name=args.profile,
        region_name=args.region
    )
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

#!/usr/bin/env python3
"""
data_security_aws - ec2_ebs_volume_kms_encryption_enabled

Ensure EBS volumes use KMS encryption instead of default encryption for better key management and audit trails.
"""

# Rule Metadata from YAML:
# Function Name: ec2_ebs_volume_kms_encryption_enabled
# Capability: DATA_PROTECTION
# Service: EC2
# Subservice: ENCRYPTION
# Description: Ensure EBS volumes use KMS encryption instead of default encryption for better key management and audit trails.
# Risk Level: HIGH
# Recommendation: Use KMS encryption for EBS volumes
# API Function: client = boto3.client('ec2')
# User Function: ec2_ebs_volume_kms_encryption_enabled()

# Import required modules
import boto3
import json
import sys
from typing import Dict, List, Any
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def load_rule_metadata(function_name: str) -> Dict[str, Any]:
    """Load rule metadata from YAML configuration."""
    return {
        "function_name": "ec2_ebs_volume_kms_encryption_enabled",
        "title": "Use KMS encryption for EBS volumes",
        "description": "Ensure EBS volumes use KMS encryption instead of default encryption for better key management and audit trails.",
        "capability": "data_protection",
        "service": "ec2",
        "subservice": "encryption",
        "risk": "HIGH",
        "existing": False
    }

def ec2_ebs_volume_kms_encryption_enabled_check(region_name: str, profile_name: str = None) -> List[Dict[str, Any]]:
    """
    Check ec2 resources for data_protection compliance.
    
    Args:
        region_name (str): AWS region name
        profile_name (str): AWS profile name (optional)
        
    Returns:
        List[Dict]: List of compliance findings
    """
    findings = []
    
    try:
        # Initialize boto3 clients
        session = boto3.Session(profile_name=profile_name)
        ec2_client = session.client('ec2', region_name=region_name)
        kms_client = session.client('kms', region_name=region_name)
        
        logger.info(f"Checking ec2 resources for data_protection compliance in region {region_name}")
        
        # Get all EBS volumes in the region
        paginator = ec2_client.get_paginator('describe_volumes')
        
        for page in paginator.paginate():
            for volume in page['Volumes']:
                volume_id = volume.get('VolumeId')
                
                try:
                    encryption_violations = []
                    compliance_details = {
                        'volume_id': volume_id,
                        'current_region': region_name,
                        'encryption_compliance_checks': []
                    }
                    
                    # Check if volume is encrypted
                    encrypted = volume.get('Encrypted', False)
                    kms_key_id = volume.get('KmsKeyId')
                    
                    if not encrypted:
                        encryption_violations.append({
                            'violation_type': 'volume_not_encrypted',
                            'message': 'EBS volume is not encrypted',
                            'severity': 'HIGH'
                        })
                    else:
                        # Volume is encrypted, check if using KMS
                        if not kms_key_id:
                            encryption_violations.append({
                                'violation_type': 'missing_kms_key',
                                'message': 'Encrypted volume missing KMS key information',
                                'severity': 'MEDIUM'
                            })
                        else:
                            # Analyze KMS key details
                            try:
                                # Get key details
                                key_response = kms_client.describe_key(KeyId=kms_key_id)
                                key_metadata = key_response.get('KeyMetadata', {})
                                
                                key_manager = key_metadata.get('KeyManager')
                                key_usage = key_metadata.get('KeyUsage')
                                key_state = key_metadata.get('KeyState')
                                key_origin = key_metadata.get('Origin')
                                
                                # Check if using AWS managed key vs customer managed key
                                if key_manager == 'AWS':
                                    encryption_violations.append({
                                        'violation_type': 'aws_managed_key',
                                        'message': 'Volume uses AWS-managed key instead of customer-managed KMS key',
                                        'key_id': kms_key_id,
                                        'key_manager': key_manager,
                                        'severity': 'MEDIUM'
                                    })
                                
                                # Check key state
                                if key_state != 'Enabled':
                                    encryption_violations.append({
                                        'violation_type': 'key_not_enabled',
                                        'message': f'KMS key is not enabled (state: {key_state})',
                                        'key_id': kms_key_id,
                                        'key_state': key_state,
                                        'severity': 'HIGH'
                                    })
                                
                                # Check key usage
                                if key_usage != 'ENCRYPT_DECRYPT':
                                    encryption_violations.append({
                                        'violation_type': 'invalid_key_usage',
                                        'message': f'KMS key usage is not ENCRYPT_DECRYPT (usage: {key_usage})',
                                        'key_id': kms_key_id,
                                        'key_usage': key_usage,
                                        'severity': 'HIGH'
                                    })
                                
                                # Check key origin
                                if key_origin not in ['AWS_KMS', 'EXTERNAL']:
                                    encryption_violations.append({
                                        'violation_type': 'unsupported_key_origin',
                                        'message': f'Unsupported key origin: {key_origin}',
                                        'key_id': kms_key_id,
                                        'key_origin': key_origin,
                                        'severity': 'MEDIUM'
                                    })
                                
                                # Get key policy for additional checks
                                try:
                                    key_policy_response = kms_client.get_key_policy(
                                        KeyId=kms_key_id,
                                        PolicyName='default'
                                    )
                                    key_policy = json.loads(key_policy_response.get('Policy', '{}'))
                                    
                                    # Check for overly permissive policies
                                    policy_violations = []
                                    for statement in key_policy.get('Statement', []):
                                        principal = statement.get('Principal', {})
                                        effect = statement.get('Effect')
                                        
                                        # Check for wildcard principals
                                        if effect == 'Allow':
                                            if isinstance(principal, str) and principal == '*':
                                                policy_violations.append('Key policy allows all principals (*)')
                                            elif isinstance(principal, dict):
                                                aws_principals = principal.get('AWS', [])
                                                if isinstance(aws_principals, str):
                                                    aws_principals = [aws_principals]
                                                if '*' in aws_principals:
                                                    policy_violations.append('Key policy allows all AWS principals')
                                    
                                    if policy_violations:
                                        encryption_violations.extend([{
                                            'violation_type': 'permissive_key_policy',
                                            'message': violation,
                                            'key_id': kms_key_id,
                                            'severity': 'HIGH'
                                        } for violation in policy_violations])
                                    
                                    compliance_details['key_policy_analysis'] = {
                                        'total_statements': len(key_policy.get('Statement', [])),
                                        'policy_violations': policy_violations
                                    }
                                    
                                except Exception as policy_error:
                                    logger.warning(f"Failed to check key policy for {kms_key_id}: {policy_error}")
                                    compliance_details['key_policy_analysis'] = {'error': str(policy_error)}
                                
                                compliance_details['kms_key_details'] = {
                                    'key_id': kms_key_id,
                                    'key_manager': key_manager,
                                    'key_usage': key_usage,
                                    'key_state': key_state,
                                    'key_origin': key_origin,
                                    'creation_date': key_metadata.get('CreationDate').isoformat() if key_metadata.get('CreationDate') else None,
                                    'description': key_metadata.get('Description'),
                                    'multi_region': key_metadata.get('MultiRegion', False)
                                }
                                
                            except Exception as kms_error:
                                logger.warning(f"Failed to check KMS key {kms_key_id}: {kms_error}")
                                encryption_violations.append({
                                    'violation_type': 'kms_key_check_failed',
                                    'message': f'Unable to verify KMS key details: {str(kms_error)}',
                                    'key_id': kms_key_id,
                                    'severity': 'MEDIUM'
                                })
                                compliance_details['kms_key_details'] = {'error': str(kms_error)}
                    
                    # Check volume tags for encryption requirements
                    tags = {tag.get('Key'): tag.get('Value') for tag in volume.get('Tags', [])}
                    data_classification = tags.get('DataClassification', '').upper()
                    compliance_framework = tags.get('ComplianceFramework', '').upper()
                    
                    # Enhanced encryption requirements for sensitive data
                    if data_classification in ['CONFIDENTIAL', 'RESTRICTED', 'SECRET']:
                        if not encrypted:
                            encryption_violations.append({
                                'violation_type': 'sensitive_data_not_encrypted',
                                'message': f'Volume with {data_classification} data classification must be encrypted',
                                'data_classification': data_classification,
                                'severity': 'CRITICAL'
                            })
                        elif kms_key_id and key_manager == 'AWS':
                            encryption_violations.append({
                                'violation_type': 'sensitive_data_aws_managed_key',
                                'message': f'Volume with {data_classification} data should use customer-managed KMS keys',
                                'data_classification': data_classification,
                                'severity': 'HIGH'
                            })
                    
                    # Compliance framework specific requirements
                    if compliance_framework in ['HIPAA', 'PCI-DSS', 'GDPR']:
                        if not encrypted:
                            encryption_violations.append({
                                'violation_type': 'compliance_encryption_required',
                                'message': f'{compliance_framework} compliance requires encryption',
                                'compliance_framework': compliance_framework,
                                'severity': 'CRITICAL'
                            })
                        elif not kms_key_id:
                            encryption_violations.append({
                                'violation_type': 'compliance_kms_required',
                                'message': f'{compliance_framework} compliance typically requires KMS encryption',
                                'compliance_framework': compliance_framework,
                                'severity': 'HIGH'
                            })
                    
                    compliance_details['encryption_compliance_checks'] = [
                        {
                            'check': 'volume_encrypted',
                            'compliant': encrypted,
                            'details': f'Volume encryption: {encrypted}'
                        },
                        {
                            'check': 'kms_key_present',
                            'compliant': bool(kms_key_id) if encrypted else None,
                            'details': f'KMS key ID: {kms_key_id or "N/A"}'
                        },
                        {
                            'check': 'customer_managed_key',
                            'compliant': key_manager == 'CUSTOMER' if kms_key_id else None,
                            'details': f'Key manager: {key_manager if kms_key_id else "N/A"}'
                        }
                    ]
                    
                    # Add volume details
                    compliance_details['volume_details'] = {
                        'volume_type': volume.get('VolumeType'),
                        'size': volume.get('Size'),
                        'state': volume.get('State'),
                        'availability_zone': volume.get('AvailabilityZone'),
                        'create_time': volume.get('CreateTime').isoformat() if volume.get('CreateTime') else None,
                        'encrypted': encrypted,
                        'iops': volume.get('Iops'),
                        'throughput': volume.get('Throughput'),
                        'snapshot_id': volume.get('SnapshotId')
                    }
                    
                    compliance_details['volume_tags'] = tags
                    
                    # Check volume attachments for additional context
                    attachments = volume.get('Attachments', [])
                    if attachments:
                        attachment_details = []
                        for attachment in attachments:
                            attachment_details.append({
                                'instance_id': attachment.get('InstanceId'),
                                'device': attachment.get('Device'),
                                'state': attachment.get('State'),
                                'attach_time': attachment.get('AttachTime').isoformat() if attachment.get('AttachTime') else None
                            })
                        compliance_details['attachments'] = attachment_details
                    
                    # Determine compliance status
                    critical_violations = len([v for v in encryption_violations if v.get('severity') in ['CRITICAL', 'HIGH']])
                    
                    if not encrypted or critical_violations > 0:
                        findings.append({
                            "region": region_name,
                            "profile": profile_name or "default",
                            "resource_type": "ec2_ebs_volume",
                            "resource_id": volume_id,
                            "status": "NON_COMPLIANT",
                            "risk_level": "HIGH",
                            "recommendation": "Enable KMS encryption for EBS volume",
                            "details": {
                                **compliance_details,
                                "violation": f"Volume has {len(encryption_violations)} encryption violations",
                                "encryption_violations": encryption_violations,
                                "critical_violations": critical_violations
                            }
                        })
                    else:
                        findings.append({
                            "region": region_name,
                            "profile": profile_name or "default",
                            "resource_type": "ec2_ebs_volume",
                            "resource_id": volume_id,
                            "status": "COMPLIANT",
                            "risk_level": "HIGH",
                            "recommendation": "EBS volume has proper KMS encryption",
                            "details": {
                                **compliance_details,
                                "minor_issues": encryption_violations if encryption_violations else None
                            }
                        })
                        
                except Exception as volume_error:
                    logger.warning(f"Failed to check volume {volume_id}: {volume_error}")
                    findings.append({
                        "region": region_name,
                        "profile": profile_name or "default",
                        "resource_type": "ec2_ebs_volume",
                        "resource_id": volume_id,
                        "status": "ERROR",
                        "risk_level": "HIGH",
                        "recommendation": "Unable to check volume encryption compliance",
                        "details": {
                            "volume_id": volume_id,
                            "error": str(volume_error)
                        }
                    })
        
        logger.info(f"Completed checking ec2_ebs_volume_kms_encryption_enabled. Found {len(findings)} findings.")
        
    except Exception as e:
        logger.error(f"Failed to check ec2_ebs_volume_kms_encryption_enabled: {e}")
        findings.append({
            "region": region_name,
            "profile": profile_name or "default",
            "resource_type": "ec2_ebs_volume",
            "resource_id": "unknown",
            "status": "ERROR",
            "risk_level": "HIGH",
            "recommendation": "Fix API access issues",
            "details": {
                "error": str(e)
            }
        })
    
    return findings

def ec2_ebs_volume_kms_encryption_enabled(region_name: str, profile_name: str = None) -> Dict[str, Any]:
    """
    Main function wrapper for ec2_ebs_volume_kms_encryption_enabled.
    
    Args:
        region_name (str): AWS region name
        profile_name (str): AWS profile name (optional)
        
    Returns:
        Dict: Results summary
    """
    COMPLIANCE_DATA = load_rule_metadata("ec2_ebs_volume_kms_encryption_enabled")
    
    # TODO: Implement SecurityEngine integration when available
    # from data_security_engine import SecurityEngine
    # engine = SecurityEngine(COMPLIANCE_DATA)
    # return engine.run_check(region_name, profile_name, ec2_ebs_volume_kms_encryption_enabled_check)
    
    # Current implementation
    findings = ec2_ebs_volume_kms_encryption_enabled_check(region_name, profile_name)
    
    # Calculate compliance statistics
    total_findings = len(findings)
    compliant_findings = len([f for f in findings if f['status'] == 'COMPLIANT'])
    non_compliant_findings = len([f for f in findings if f['status'] == 'NON_COMPLIANT'])
    error_findings = len([f for f in findings if f['status'] == 'ERROR'])
    
    return {
        "function_name": "ec2_ebs_volume_kms_encryption_enabled",
        "region": region_name,
        "profile": profile_name or "default",
        "total_findings": total_findings,
        "compliant_count": compliant_findings,
        "non_compliant_count": non_compliant_findings,
        "error_count": error_findings,
        "compliance_rate": (compliant_findings / total_findings * 100) if total_findings > 0 else 0,
        "findings": findings
    }

def main():
    """CLI entry point for ec2_ebs_volume_kms_encryption_enabled."""
    # TODO: Implement setup_command_line_interface() when data_security_engine is available
    # from data_security_engine import setup_command_line_interface, save_results, exit_with_status
    # args = setup_command_line_interface()
    # results = ec2_ebs_volume_kms_encryption_enabled(args.region, args.profile)
    # save_results(results, args.output_file)
    # exit_with_status(results)
    
    # Current CLI implementation
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Ensure EBS volumes use KMS encryption instead of default encryption for better key management and audit trails."
    )
    parser.add_argument("--region", default="us-east-1", help="AWS region")
    parser.add_argument("--profile", help="AWS profile name")
    parser.add_argument("--output", help="Output file for results (JSON format)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        results = ec2_ebs_volume_kms_encryption_enabled(args.region, args.profile)
        
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"Results saved to {args.output}")
        else:
            print(json.dumps(results, indent=2))
            
        # Exit with appropriate code
        if results['error_count'] > 0:
            sys.exit(2)  # Errors encountered
        elif results['non_compliant_count'] > 0:
            sys.exit(1)  # Non-compliant resources found
        else:
            sys.exit(0)  # All compliant
            
    except Exception as e:
        logger.error(f"Execution failed: {e}")
        sys.exit(3)

if __name__ == "__main__":
    main()

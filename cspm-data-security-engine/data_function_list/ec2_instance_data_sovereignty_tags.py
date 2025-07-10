#!/usr/bin/env python3
"""
data_security_aws - ec2_instance_data_sovereignty_tags

Ensure EC2 instances are tagged with data sovereignty and jurisdiction information for compliance tracking.
"""

# Rule Metadata from YAML:
# Function Name: ec2_instance_data_sovereignty_tags
# Capability: DATA_RESIDENCY
# Service: EC2
# Subservice: TAGGING
# Description: Ensure EC2 instances are tagged with data sovereignty and jurisdiction information for compliance tracking.
# Risk Level: LOW
# Recommendation: Tag EC2 instances with data sovereignty information
# API Function: client = boto3.client('ec2')
# User Function: ec2_instance_data_sovereignty_tags()

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
        "function_name": "ec2_instance_data_sovereignty_tags",
        "title": "Tag EC2 instances with data sovereignty information",
        "description": "Ensure EC2 instances are tagged with data sovereignty and jurisdiction information for compliance tracking.",
        "capability": "data_residency",
        "service": "ec2",
        "subservice": "tagging",
        "risk": "LOW",
        "existing": False
    }

def ec2_instance_data_sovereignty_tags_check(region_name: str, profile_name: str = None) -> List[Dict[str, Any]]:
    """
    Check ec2 resources for data_residency compliance.
    
    Args:
        region_name (str): AWS region name
        profile_name (str): AWS profile name (optional)
        
    Returns:
        List[Dict]: List of compliance findings
    """
    findings = []
    
    # Define required data sovereignty tags and their valid values
    required_sovereignty_tags = {
        'DataJurisdiction': ['US', 'EU', 'UK', 'CA', 'AU', 'JP', 'APAC'],
        'DataResidency': ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 
                         'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-central-1', 'eu-north-1',
                         'ca-central-1', 'ap-southeast-2', 'ap-northeast-1'],
        'ComplianceFramework': ['GDPR', 'HIPAA', 'SOX', 'FISMA', 'PCI-DSS', 'SOC2', 'ISO27001', 'DPA'],
        'DataClassification': ['PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'RESTRICTED'],
        'DataController': [],  # Free text but required for EU/UK
        'LegalBasis': ['CONSENT', 'CONTRACT', 'LEGAL_OBLIGATION', 'VITAL_INTERESTS', 'PUBLIC_TASK', 'LEGITIMATE_INTERESTS']
    }
    
    # Optional but recommended tags
    optional_tags = {
        'DataProcessor': [],  # Free text
        'RetentionPeriod': [],  # Format: P30D, P1Y, etc.
        'DataSubject': ['CUSTOMER', 'EMPLOYEE', 'PARTNER', 'VENDOR'],
        'SovereigntyLevel': ['STRICT', 'MODERATE', 'FLEXIBLE'],
        'CrossBorderTransfer': ['ALLOWED', 'RESTRICTED', 'PROHIBITED'],
        'ComplianceOfficer': [],  # Free text - email address
        'DataGovernor': []  # Free text - responsible person
    }
    
    try:
        # Initialize boto3 client
        session = boto3.Session(profile_name=profile_name)
        ec2_client = session.client('ec2', region_name=region_name)
        
        logger.info(f"Checking ec2 resources for data_residency compliance in region {region_name}")
        
        # Get all EC2 instances in the region
        paginator = ec2_client.get_paginator('describe_instances')
        
        for page in paginator.paginate():
            for reservation in page['Reservations']:
                for instance in reservation['Instances']:
                    instance_id = instance.get('InstanceId')
                    
                    try:
                        tag_violations = []
                        compliance_details = {
                            'instance_id': instance_id,
                            'region': region_name,
                            'tag_compliance_checks': []
                        }
                        
                        # Get instance tags
                        tags = {tag.get('Key'): tag.get('Value') for tag in instance.get('Tags', [])}
                        
                        # Check for required sovereignty tags
                        missing_required_tags = []
                        invalid_tag_values = []
                        
                        for required_tag, valid_values in required_sovereignty_tags.items():
                            tag_value = tags.get(required_tag, '')
                            
                            if not tag_value:
                                missing_required_tags.append(required_tag)
                                tag_violations.append({
                                    'violation_type': 'missing_required_tag',
                                    'tag_name': required_tag,
                                    'message': f"Missing required data sovereignty tag: {required_tag}",
                                    'valid_values': valid_values if valid_values else 'Free text'
                                })
                            elif valid_values and tag_value.upper() not in [v.upper() for v in valid_values]:
                                invalid_tag_values.append({
                                    'tag_name': required_tag,
                                    'current_value': tag_value,
                                    'valid_values': valid_values
                                })
                                tag_violations.append({
                                    'violation_type': 'invalid_tag_value',
                                    'tag_name': required_tag,
                                    'current_value': tag_value,
                                    'message': f"Invalid value for {required_tag}: {tag_value}",
                                    'valid_values': valid_values
                                })
                            
                            compliance_details['tag_compliance_checks'].append({
                                'tag': required_tag,
                                'present': bool(tag_value),
                                'value': tag_value,
                                'valid': tag_value.upper() in [v.upper() for v in valid_values] if valid_values else bool(tag_value),
                                'required': True
                            })
                        
                        # Check jurisdiction-specific requirements
                        data_jurisdiction = tags.get('DataJurisdiction', '').upper()
                        compliance_framework = tags.get('ComplianceFramework', '').upper()
                        
                        # EU/UK specific requirements
                        if data_jurisdiction in ['EU', 'UK'] or 'GDPR' in compliance_framework or 'DPA' in compliance_framework:
                            if not tags.get('DataController'):
                                tag_violations.append({
                                    'violation_type': 'missing_jurisdiction_tag',
                                    'tag_name': 'DataController',
                                    'message': 'EU/UK instances must have DataController tag',
                                    'jurisdiction': data_jurisdiction
                                })
                            
                            if not tags.get('LegalBasis'):
                                tag_violations.append({
                                    'violation_type': 'missing_jurisdiction_tag',
                                    'tag_name': 'LegalBasis',
                                    'message': 'EU/UK instances must have LegalBasis tag',
                                    'jurisdiction': data_jurisdiction
                                })
                        
                        # US compliance requirements
                        if data_jurisdiction == 'US' and any(framework in compliance_framework 
                                                           for framework in ['HIPAA', 'SOX', 'FISMA']):
                            if not tags.get('ComplianceOfficer'):
                                tag_violations.append({
                                    'violation_type': 'missing_jurisdiction_tag',
                                    'tag_name': 'ComplianceOfficer',
                                    'message': 'US regulated instances should have ComplianceOfficer tag',
                                    'jurisdiction': data_jurisdiction
                                })
                        
                        # Check data residency consistency
                        data_residency = tags.get('DataResidency', '').lower()
                        if data_residency and data_residency != region_name:
                            tag_violations.append({
                                'violation_type': 'residency_mismatch',
                                'message': f"DataResidency tag ({data_residency}) doesn't match instance region ({region_name})",
                                'tagged_region': data_residency,
                                'actual_region': region_name
                            })
                        
                        # Check for data classification consistency
                        data_classification = tags.get('DataClassification', '').upper()
                        if data_classification in ['CONFIDENTIAL', 'RESTRICTED']:
                            # High-sensitivity data should have strict sovereignty controls
                            sovereignty_level = tags.get('SovereigntyLevel', '').upper()
                            if sovereignty_level != 'STRICT':
                                tag_violations.append({
                                    'violation_type': 'classification_sovereignty_mismatch',
                                    'message': f"High sensitivity data ({data_classification}) should have STRICT sovereignty level",
                                    'data_classification': data_classification,
                                    'sovereignty_level': sovereignty_level
                                })
                            
                            cross_border = tags.get('CrossBorderTransfer', '').upper()
                            if cross_border == 'ALLOWED':
                                tag_violations.append({
                                    'violation_type': 'classification_transfer_mismatch',
                                    'message': f"High sensitivity data ({data_classification}) should not allow cross-border transfer",
                                    'data_classification': data_classification,
                                    'cross_border_transfer': cross_border
                                })
                        
                        # Check optional tag validity
                        for optional_tag, valid_values in optional_tags.items():
                            tag_value = tags.get(optional_tag, '')
                            if tag_value and valid_values and tag_value.upper() not in [v.upper() for v in valid_values]:
                                tag_violations.append({
                                    'violation_type': 'invalid_optional_tag_value',
                                    'tag_name': optional_tag,
                                    'current_value': tag_value,
                                    'message': f"Invalid value for optional tag {optional_tag}: {tag_value}",
                                    'valid_values': valid_values
                                })
                            
                            compliance_details['tag_compliance_checks'].append({
                                'tag': optional_tag,
                                'present': bool(tag_value),
                                'value': tag_value,
                                'valid': tag_value.upper() in [v.upper() for v in valid_values] if valid_values and tag_value else True,
                                'required': False
                            })
                        
                        # Check retention period format
                        retention_period = tags.get('RetentionPeriod', '')
                        if retention_period:
                            import re
                            # ISO 8601 duration format: P[n]Y[n]M[n]DT[n]H[n]M[n]S or simplified P[n]D, P[n]M, P[n]Y
                            if not re.match(r'^P(\d+Y)?(\d+M)?(\d+D)?(T(\d+H)?(\d+M)?(\d+S)?)?$|^P\d+[DMY]$', retention_period):
                                tag_violations.append({
                                    'violation_type': 'invalid_retention_format',
                                    'tag_name': 'RetentionPeriod',
                                    'current_value': retention_period,
                                    'message': f"Invalid retention period format: {retention_period}",
                                    'expected_format': 'ISO 8601 duration (e.g., P30D, P1Y, P6M)'
                                })
                        
                        # Check email format for compliance officer
                        compliance_officer = tags.get('ComplianceOfficer', '')
                        if compliance_officer:
                            import re
                            if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', compliance_officer):
                                tag_violations.append({
                                    'violation_type': 'invalid_email_format',
                                    'tag_name': 'ComplianceOfficer',
                                    'current_value': compliance_officer,
                                    'message': f"Invalid email format for ComplianceOfficer: {compliance_officer}",
                                    'expected_format': 'Valid email address'
                                })
                        
                        # Add instance details
                        compliance_details['instance_details'] = {
                            'instance_type': instance.get('InstanceType'),
                            'state': instance.get('State', {}).get('Name'),
                            'launch_time': instance.get('LaunchTime').isoformat() if instance.get('LaunchTime') else None,
                            'availability_zone': instance.get('Placement', {}).get('AvailabilityZone'),
                            'vpc_id': instance.get('VpcId'),
                            'subnet_id': instance.get('SubnetId'),
                            'private_ip': instance.get('PrivateIpAddress'),
                            'public_ip': instance.get('PublicIpAddress'),
                            'security_groups': [sg.get('GroupName') for sg in instance.get('SecurityGroups', [])],
                            'image_id': instance.get('ImageId'),
                            'key_name': instance.get('KeyName')
                        }
                        
                        compliance_details['all_tags'] = tags
                        compliance_details['sovereignty_tags'] = {k: v for k, v in tags.items() 
                                                                if k in list(required_sovereignty_tags.keys()) + list(optional_tags.keys())}
                        
                        # Calculate tag completeness score
                        total_required_tags = len(required_sovereignty_tags)
                        present_required_tags = len([tag for tag in required_sovereignty_tags.keys() if tags.get(tag)])
                        
                        # Adjust for jurisdiction-specific requirements
                        if data_jurisdiction in ['EU', 'UK'] or 'GDPR' in compliance_framework:
                            total_required_tags += 2  # DataController and LegalBasis
                            if tags.get('DataController'):
                                present_required_tags += 1
                            if tags.get('LegalBasis'):
                                present_required_tags += 1
                        
                        if data_jurisdiction == 'US' and any(framework in compliance_framework 
                                                           for framework in ['HIPAA', 'SOX', 'FISMA']):
                            total_required_tags += 1  # ComplianceOfficer
                            if tags.get('ComplianceOfficer'):
                                present_required_tags += 1
                        
                        tag_completeness = (present_required_tags / total_required_tags * 100) if total_required_tags > 0 else 0
                        compliance_details['tag_completeness_percentage'] = round(tag_completeness, 2)
                        
                        # Determine compliance status
                        critical_violations = [v for v in tag_violations if v.get('violation_type') in 
                                             ['missing_required_tag', 'residency_mismatch', 'classification_sovereignty_mismatch']]
                        
                        if critical_violations or len(missing_required_tags) > 0:
                            findings.append({
                                "region": region_name,
                                "profile": profile_name or "default",
                                "resource_type": "ec2_instance",
                                "resource_id": instance_id,
                                "status": "NON_COMPLIANT",
                                "risk_level": "LOW",
                                "recommendation": "Tag EC2 instance with required data sovereignty information",
                                "details": {
                                    **compliance_details,
                                    "violation": f"Instance missing {len(missing_required_tags)} required tags and has {len(tag_violations)} tag violations",
                                    "missing_required_tags": missing_required_tags,
                                    "tag_violations": tag_violations,
                                    "critical_violations": critical_violations
                                }
                            })
                        else:
                            findings.append({
                                "region": region_name,
                                "profile": profile_name or "default",
                                "resource_type": "ec2_instance",
                                "resource_id": instance_id,
                                "status": "COMPLIANT",
                                "risk_level": "LOW",
                                "recommendation": "Instance properly tagged with data sovereignty information",
                                "details": compliance_details
                            })
                            
                    except Exception as instance_error:
                        logger.warning(f"Failed to check instance {instance_id}: {instance_error}")
                        findings.append({
                            "region": region_name,
                            "profile": profile_name or "default",
                            "resource_type": "ec2_instance",
                            "resource_id": instance_id,
                            "status": "ERROR",
                            "risk_level": "LOW",
                            "recommendation": "Unable to check instance data sovereignty tags",
                            "details": {
                                "instance_id": instance_id,
                                "error": str(instance_error)
                            }
                        })
        
        logger.info(f"Completed checking ec2_instance_data_sovereignty_tags. Found {len(findings)} findings.")
        
    except Exception as e:
        logger.error(f"Failed to check ec2_instance_data_sovereignty_tags: {e}")
        findings.append({
            "region": region_name,
            "profile": profile_name or "default",
            "resource_type": "ec2_instance",
            "resource_id": "unknown",
            "status": "ERROR",
            "risk_level": "LOW",
            "recommendation": "Fix API access issues",
            "details": {
                "error": str(e)
            }
        })
    
    return findings

def ec2_instance_data_sovereignty_tags(region_name: str, profile_name: str = None) -> Dict[str, Any]:
    """
    Main function wrapper for ec2_instance_data_sovereignty_tags.
    
    Args:
        region_name (str): AWS region name
        profile_name (str): AWS profile name (optional)
        
    Returns:
        Dict: Results summary
    """
    COMPLIANCE_DATA = load_rule_metadata("ec2_instance_data_sovereignty_tags")
    
    # TODO: Implement SecurityEngine integration when available
    # from data_security_engine import SecurityEngine
    # engine = SecurityEngine(COMPLIANCE_DATA)
    # return engine.run_check(region_name, profile_name, ec2_instance_data_sovereignty_tags_check)
    
    # Current implementation
    findings = ec2_instance_data_sovereignty_tags_check(region_name, profile_name)
    
    # Calculate compliance statistics
    total_findings = len(findings)
    compliant_findings = len([f for f in findings if f['status'] == 'COMPLIANT'])
    non_compliant_findings = len([f for f in findings if f['status'] == 'NON_COMPLIANT'])
    error_findings = len([f for f in findings if f['status'] == 'ERROR'])
    
    return {
        "function_name": "ec2_instance_data_sovereignty_tags",
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
    """CLI entry point for ec2_instance_data_sovereignty_tags."""
    # TODO: Implement setup_command_line_interface() when data_security_engine is available
    # from data_security_engine import setup_command_line_interface, save_results, exit_with_status
    # args = setup_command_line_interface()
    # results = ec2_instance_data_sovereignty_tags(args.region, args.profile)
    # save_results(results, args.output_file)
    # exit_with_status(results)
    
    # Current CLI implementation
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Ensure EC2 instances are tagged with data sovereignty and jurisdiction information for compliance tracking."
    )
    parser.add_argument("--region", default="us-east-1", help="AWS region")
    parser.add_argument("--profile", help="AWS profile name")
    parser.add_argument("--output", help="Output file for results (JSON format)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        results = ec2_instance_data_sovereignty_tags(args.region, args.profile)
        
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

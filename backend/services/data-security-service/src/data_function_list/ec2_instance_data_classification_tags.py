#!/usr/bin/env python3
"""
data_security_aws - ec2_instance_data_classification_tags

Ensure EC2 instances are tagged with appropriate data classification levels for governance and compliance tracking.
"""

# Rule Metadata from YAML:
# Function Name: ec2_instance_data_classification_tags
# Capability: DATA_PROTECTION
# Service: EC2
# Subservice: TAGGING
# Description: Ensure EC2 instances are tagged with appropriate data classification levels for governance and compliance tracking.
# Risk Level: LOW
# Recommendation: Tag EC2 instances with data classification
# API Function: client = boto3.client('ec2')
# User Function: ec2_instance_data_classification_tags()

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
        "function_name": "ec2_instance_data_classification_tags",
        "title": "Tag EC2 instances with data classification",
        "description": "Ensure EC2 instances are tagged with appropriate data classification levels for governance and compliance tracking.",
        "capability": "data_protection",
        "service": "ec2",
        "subservice": "tagging",
        "risk": "LOW",
        "existing": False
    }

def ec2_instance_data_classification_tags_check(region_name: str, profile_name: str = None) -> List[Dict[str, Any]]:
    """
    Check ec2 resources for data_protection compliance.
    
    Args:
        region_name (str): AWS region name
        profile_name (str): AWS profile name (optional)
        
    Returns:
        List[Dict]: List of compliance findings
    """
    findings = []
    
    # Define required data classification tags and valid values
    required_tags = {
        'DataClassification': ['PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'RESTRICTED', 'SECRET'],
        'DataSensitivity': ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
        'ComplianceFramework': ['GDPR', 'HIPAA', 'PCI-DSS', 'SOX', 'ISO27001', 'SOC2', 'NONE'],
        'DataRetention': ['30DAYS', '90DAYS', '1YEAR', '3YEARS', '7YEARS', 'INDEFINITE'],
        'DataOwner': []  # Free text, but should be present
    }
    
    # Optional but recommended tags
    recommended_tags = {
        'Environment': ['DEV', 'TEST', 'STAGING', 'PROD'],
        'Project': [],  # Free text
        'CostCenter': [],  # Free text
        'BusinessUnit': [],  # Free text
        'DataRegion': [],  # Should match current region
        'BackupRequired': ['TRUE', 'FALSE'],
        'MonitoringLevel': ['BASIC', 'STANDARD', 'ENHANCED', 'COMPREHENSIVE']
    }
    
    try:
        # Initialize boto3 client
        session = boto3.Session(profile_name=profile_name)
        ec2_client = session.client('ec2', region_name=region_name)
        
        logger.info(f"Checking ec2 resources for data_protection compliance in region {region_name}")
        
        # Get all EC2 instances in the region
        paginator = ec2_client.get_paginator('describe_instances')
        
        for page in paginator.paginate():
            for reservation in page['Reservations']:
                for instance in reservation['Instances']:
                    instance_id = instance.get('InstanceId')
                    
                    try:
                        tagging_violations = []
                        compliance_details = {
                            'instance_id': instance_id,
                            'current_region': region_name,
                            'tagging_compliance_checks': []
                        }
                        
                        # Get instance tags
                        tags = {tag.get('Key'): tag.get('Value') for tag in instance.get('Tags', [])}
                        
                        # Check required tags
                        missing_required_tags = []
                        invalid_tag_values = []
                        
                        for required_tag, valid_values in required_tags.items():
                            tag_value = tags.get(required_tag, '').upper()
                            
                            if not tag_value:
                                missing_required_tags.append(required_tag)
                                tagging_violations.append({
                                    'violation_type': 'missing_required_tag',
                                    'message': f"Missing required tag: {required_tag}",
                                    'tag_name': required_tag,
                                    'valid_values': valid_values
                                })
                            elif valid_values and tag_value not in valid_values:
                                invalid_tag_values.append({
                                    'tag_name': required_tag,
                                    'current_value': tag_value,
                                    'valid_values': valid_values
                                })
                                tagging_violations.append({
                                    'violation_type': 'invalid_tag_value',
                                    'message': f"Invalid value for {required_tag}: {tag_value}. Valid values: {', '.join(valid_values)}",
                                    'tag_name': required_tag,
                                    'current_value': tag_value,
                                    'valid_values': valid_values
                                })
                            
                            compliance_details['tagging_compliance_checks'].append({
                                'check': f'required_tag_{required_tag.lower()}',
                                'tag_name': required_tag,
                                'present': bool(tag_value),
                                'valid': tag_value in valid_values if valid_values else bool(tag_value),
                                'current_value': tags.get(required_tag, '')
                            })
                        
                        # Check recommended tags
                        missing_recommended_tags = []
                        
                        for recommended_tag, valid_values in recommended_tags.items():
                            tag_value = tags.get(recommended_tag, '').upper()
                            
                            if not tag_value:
                                missing_recommended_tags.append(recommended_tag)
                            elif valid_values and tag_value not in valid_values:
                                tagging_violations.append({
                                    'violation_type': 'invalid_recommended_tag_value',
                                    'message': f"Invalid value for recommended tag {recommended_tag}: {tag_value}. Valid values: {', '.join(valid_values)}",
                                    'tag_name': recommended_tag,
                                    'current_value': tag_value,
                                    'valid_values': valid_values,
                                    'severity': 'LOW'
                                })
                            
                            compliance_details['tagging_compliance_checks'].append({
                                'check': f'recommended_tag_{recommended_tag.lower()}',
                                'tag_name': recommended_tag,
                                'present': bool(tag_value),
                                'valid': tag_value in valid_values if valid_values else bool(tag_value),
                                'current_value': tags.get(recommended_tag, ''),
                                'optional': True
                            })
                        
                        # Validate data classification consistency
                        data_classification = tags.get('DataClassification', '').upper()
                        data_sensitivity = tags.get('DataSensitivity', '').upper()
                        environment = tags.get('Environment', '').upper()
                        
                        # Check classification-sensitivity consistency
                        if data_classification and data_sensitivity:
                            classification_sensitivity_mapping = {
                                'PUBLIC': ['LOW'],
                                'INTERNAL': ['LOW', 'MEDIUM'],
                                'CONFIDENTIAL': ['MEDIUM', 'HIGH'],
                                'RESTRICTED': ['HIGH', 'CRITICAL'],
                                'SECRET': ['CRITICAL']
                            }
                            
                            expected_sensitivities = classification_sensitivity_mapping.get(data_classification, [])
                            if expected_sensitivities and data_sensitivity not in expected_sensitivities:
                                tagging_violations.append({
                                    'violation_type': 'classification_sensitivity_mismatch',
                                    'message': f"Data classification {data_classification} inconsistent with sensitivity {data_sensitivity}",
                                    'classification': data_classification,
                                    'sensitivity': data_sensitivity,
                                    'expected_sensitivities': expected_sensitivities
                                })
                        
                        # Check environment-specific requirements
                        if environment == 'PROD':
                            # Production instances should have stricter requirements
                            prod_violations = []
                            
                            if not tags.get('DataOwner'):
                                prod_violations.append('DataOwner tag required for production instances')
                            
                            if not tags.get('BackupRequired'):
                                prod_violations.append('BackupRequired tag required for production instances')
                            
                            if data_classification in ['CONFIDENTIAL', 'RESTRICTED', 'SECRET']:
                                if not tags.get('MonitoringLevel'):
                                    prod_violations.append('MonitoringLevel tag required for sensitive production data')
                                elif tags.get('MonitoringLevel', '').upper() not in ['ENHANCED', 'COMPREHENSIVE']:
                                    prod_violations.append('Enhanced monitoring required for sensitive production data')
                            
                            if prod_violations:
                                tagging_violations.extend([{
                                    'violation_type': 'production_requirements',
                                    'message': violation,
                                    'environment': 'PROD'
                                } for violation in prod_violations])
                        
                        # Check region consistency
                        data_region = tags.get('DataRegion', '').lower()
                        if data_region and data_region.replace('_', '-') != region_name:
                            tagging_violations.append({
                                'violation_type': 'region_tag_mismatch',
                                'message': f"DataRegion tag ({data_region}) does not match actual region ({region_name})",
                                'tagged_region': data_region,
                                'actual_region': region_name
                            })
                        
                        # Check for compliance framework specific requirements
                        compliance_framework = tags.get('ComplianceFramework', '').upper()
                        if compliance_framework and compliance_framework != 'NONE':
                            framework_violations = []
                            
                            if compliance_framework in ['GDPR', 'HIPAA', 'PCI-DSS']:
                                if data_classification not in ['CONFIDENTIAL', 'RESTRICTED', 'SECRET']:
                                    framework_violations.append(f'{compliance_framework} compliance typically requires higher data classification')
                                
                                if not tags.get('DataRetention'):
                                    framework_violations.append(f'DataRetention tag required for {compliance_framework} compliance')
                            
                            if framework_violations:
                                tagging_violations.extend([{
                                    'violation_type': 'compliance_framework_requirements',
                                    'message': violation,
                                    'framework': compliance_framework
                                } for violation in framework_violations])
                        
                        # Calculate tagging score
                        required_tags_present = len(required_tags) - len(missing_required_tags)
                        recommended_tags_present = len(recommended_tags) - len(missing_recommended_tags)
                        
                        tagging_score = {
                            'required_tags_score': required_tags_present / len(required_tags) * 100,
                            'recommended_tags_score': recommended_tags_present / len(recommended_tags) * 100,
                            'total_violations': len(tagging_violations)
                        }
                        
                        # Add detailed information
                        compliance_details['instance_details'] = {
                            'instance_type': instance.get('InstanceType'),
                            'state': instance.get('State', {}).get('Name'),
                            'platform': instance.get('Platform'),
                            'vpc_id': instance.get('VpcId'),
                            'subnet_id': instance.get('SubnetId'),
                            'availability_zone': instance.get('Placement', {}).get('AvailabilityZone'),
                            'launch_time': instance.get('LaunchTime').isoformat() if instance.get('LaunchTime') else None
                        }
                        
                        compliance_details['current_tags'] = tags
                        compliance_details['missing_required_tags'] = missing_required_tags
                        compliance_details['missing_recommended_tags'] = missing_recommended_tags
                        compliance_details['invalid_tag_values'] = invalid_tag_values
                        compliance_details['tagging_score'] = tagging_score
                        
                        # Determine compliance status
                        critical_violations = len([v for v in tagging_violations if v.get('violation_type') in 
                                                 ['missing_required_tag', 'invalid_tag_value', 'classification_sensitivity_mismatch']])
                        
                        if critical_violations > 0 or tagging_score['required_tags_score'] < 80:
                            findings.append({
                                "region": region_name,
                                "profile": profile_name or "default",
                                "resource_type": "ec2_instance",
                                "resource_id": instance_id,
                                "status": "NON_COMPLIANT",
                                "risk_level": "LOW",
                                "recommendation": "Ensure EC2 instance has proper data classification tags",
                                "details": {
                                    **compliance_details,
                                    "violation": f"Instance has {len(tagging_violations)} tagging violations",
                                    "tagging_violations": tagging_violations,
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
                                "recommendation": "EC2 instance has adequate data classification tags",
                                "details": {
                                    **compliance_details,
                                    "minor_issues": tagging_violations if tagging_violations else None
                                }
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
                            "recommendation": "Unable to check instance data classification tags",
                            "details": {
                                "instance_id": instance_id,
                                "error": str(instance_error)
                            }
                        })
        
        logger.info(f"Completed checking ec2_instance_data_classification_tags. Found {len(findings)} findings.")
        
    except Exception as e:
        logger.error(f"Failed to check ec2_instance_data_classification_tags: {e}")
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

def ec2_instance_data_classification_tags(region_name: str, profile_name: str = None) -> Dict[str, Any]:
    """
    Main function wrapper for ec2_instance_data_classification_tags.
    
    Args:
        region_name (str): AWS region name
        profile_name (str): AWS profile name (optional)
        
    Returns:
        Dict: Results summary
    """
    COMPLIANCE_DATA = load_rule_metadata("ec2_instance_data_classification_tags")
    
    # TODO: Implement SecurityEngine integration when available
    # from data_security_engine import SecurityEngine
    # engine = SecurityEngine(COMPLIANCE_DATA)
    # return engine.run_check(region_name, profile_name, ec2_instance_data_classification_tags_check)
    
    # Current implementation
    findings = ec2_instance_data_classification_tags_check(region_name, profile_name)
    
    # Calculate compliance statistics
    total_findings = len(findings)
    compliant_findings = len([f for f in findings if f['status'] == 'COMPLIANT'])
    non_compliant_findings = len([f for f in findings if f['status'] == 'NON_COMPLIANT'])
    error_findings = len([f for f in findings if f['status'] == 'ERROR'])
    
    return {
        "function_name": "ec2_instance_data_classification_tags",
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
    """CLI entry point for ec2_instance_data_classification_tags."""
    # TODO: Implement setup_command_line_interface() when data_security_engine is available
    # from data_security_engine import setup_command_line_interface, save_results, exit_with_status
    # args = setup_command_line_interface()
    # results = ec2_instance_data_classification_tags(args.region, args.profile)
    # save_results(results, args.output_file)
    # exit_with_status(results)
    
    # Current CLI implementation
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Ensure EC2 instances are tagged with appropriate data classification levels for governance and compliance tracking."
    )
    parser.add_argument("--region", default="us-east-1", help="AWS region")
    parser.add_argument("--profile", help="AWS profile name")
    parser.add_argument("--output", help="Output file for results (JSON format)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        results = ec2_instance_data_classification_tags(args.region, args.profile)
        
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

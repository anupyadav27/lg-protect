#!/usr/bin/env python3
"""
data_security_aws - kms_key_data_sovereignty_tags

Ensure KMS keys are tagged with data sovereignty and jurisdiction information for compliance tracking.
"""

# Rule Metadata from YAML:
# Function Name: kms_key_data_sovereignty_tags
# Capability: DATA_RESIDENCY
# Service: KMS
# Subservice: TAGGING
# Description: Ensure KMS keys are tagged with data sovereignty and jurisdiction information for compliance tracking.
# Risk Level: LOW
# Recommendation: Tag KMS keys with data sovereignty information
# API Function: client = boto3.client('kms')
# User Function: kms_key_data_sovereignty_tags()

# Import required modules
import boto3
import json
import sys
import re
from typing import Dict, List, Any
import logging
from botocore.exceptions import ClientError, NoCredentialsError

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def load_rule_metadata(function_name: str) -> Dict[str, Any]:
    """Load rule metadata from YAML configuration."""
    return {
        "function_name": "kms_key_data_sovereignty_tags",
        "title": "Tag KMS keys with data sovereignty information",
        "description": "Ensure KMS keys are tagged with data sovereignty and jurisdiction information for compliance tracking.",
        "capability": "data_residency",
        "service": "kms",
        "subservice": "tagging",
        "risk": "LOW",
        "existing": False
    }

def kms_key_data_sovereignty_tags_check(region_name: str, profile_name: str = None) -> List[Dict[str, Any]]:
    """
    Check KMS keys for data sovereignty and jurisdiction tagging compliance.
    
    Args:
        region_name (str): AWS region name
        profile_name (str): AWS profile name (optional)
        
    Returns:
        List[Dict]: List of compliance findings
    """
    findings = []
    
    try:
        # Initialize boto3 client
        session = boto3.Session(profile_name=profile_name)
        kms_client = session.client('kms', region_name=region_name)
        
        logger.info(f"Checking KMS keys for data sovereignty tagging compliance in region {region_name}")
        
        # Required data sovereignty tags
        required_base_tags = [
            'DataJurisdiction',
            'DataResidency', 
            'ComplianceFramework',
            'DataClassification'
        ]
        
        # Jurisdiction-specific required tags
        jurisdiction_specific_tags = {
            'EU': ['DataController', 'LegalBasis', 'DataSubject'],
            'US': ['ComplianceOfficer'],
            'CA': ['PrivacyOfficer'],
            'AU': ['PrivacyOfficer'],
            'UK': ['DataController', 'LegalBasis']
        }
        
        # Valid values for specific tags
        valid_jurisdictions = ['US', 'EU', 'CA', 'AU', 'UK', 'APAC', 'LATAM', 'MEA']
        valid_classifications = ['PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'RESTRICTED']
        valid_frameworks = ['GDPR', 'CCPA', 'HIPAA', 'SOX', 'PCI-DSS', 'ISO27001', 'PIPEDA', 'PRIVACY_ACT']
        valid_sovereignty_levels = ['STRICT', 'MODERATE', 'FLEXIBLE']
        valid_transfer_options = ['PROHIBITED', 'RESTRICTED', 'ALLOWED']
        valid_legal_basis = ['CONSENT', 'CONTRACT', 'LEGAL_OBLIGATION', 'VITAL_INTERESTS', 'PUBLIC_TASK', 'LEGITIMATE_INTERESTS']
        valid_data_subjects = ['CUSTOMER', 'EMPLOYEE', 'PARTNER', 'PROSPECT', 'VENDOR']
        
        # Get all KMS keys (both customer-managed and AWS-managed)
        paginator = kms_client.get_paginator('list_keys')
        
        for page in paginator.paginate():
            for key in page['Keys']:
                key_id = key['KeyId']
                key_arn = key['KeyArn']
                
                try:
                    # Get key details
                    key_details = kms_client.describe_key(KeyId=key_id)['KeyMetadata']
                    key_manager = key_details.get('KeyManager', 'CUSTOMER')
                    key_usage = key_details.get('KeyUsage', 'ENCRYPT_DECRYPT')
                    key_state = key_details.get('KeyState', 'Unknown')
                    key_spec = key_details.get('KeySpec', 'SYMMETRIC_DEFAULT')
                    
                    # Skip AWS-managed keys for data sovereignty tagging requirements
                    if key_manager == 'AWS':
                        logger.debug(f"Skipping AWS-managed key: {key_id}")
                        continue
                    
                    # Skip if key is not enabled
                    if key_state not in ['Enabled', 'Disabled']:
                        logger.debug(f"Skipping key in state {key_state}: {key_id}")
                        continue
                    
                    # Get tags for the key
                    try:
                        tags_response = kms_client.list_resource_tags(KeyId=key_id)
                        key_tags = {tag['TagKey']: tag['TagValue'] for tag in tags_response.get('Tags', [])}
                    except ClientError as e:
                        if e.response['Error']['Code'] in ['AccessDenied', 'KMSInvalidStateException']:
                            logger.warning(f"Cannot access tags for key {key_id}: {e}")
                            findings.append({
                                "region": region_name,
                                "profile": profile_name or "default",
                                "resource_type": "kms_key",
                                "resource_id": key_arn,
                                "status": "ERROR",
                                "risk_level": "MEDIUM",
                                "recommendation": "Ensure proper permissions to access KMS key tags",
                                "details": {
                                    "key_id": key_id,
                                    "key_arn": key_arn,
                                    "error": f"Cannot access tags: {str(e)}",
                                    "key_manager": key_manager,
                                    "key_state": key_state
                                }
                            })
                            continue
                        else:
                            raise
                    
                    # Check for required tags
                    missing_required_tags = []
                    invalid_tag_values = []
                    tag_violations = []
                    sovereignty_tags = {}
                    
                    # Check base required tags
                    for tag in required_base_tags:
                        if tag not in key_tags:
                            missing_required_tags.append(tag)
                        else:
                            sovereignty_tags[tag] = key_tags[tag]
                    
                    # Validate tag values
                    if 'DataJurisdiction' in key_tags:
                        jurisdiction = key_tags['DataJurisdiction'].upper()
                        if jurisdiction not in valid_jurisdictions:
                            invalid_tag_values.append({
                                'tag_name': 'DataJurisdiction',
                                'current_value': key_tags['DataJurisdiction'],
                                'valid_values': valid_jurisdictions
                            })
                    
                    if 'DataClassification' in key_tags:
                        classification = key_tags['DataClassification'].upper()
                        if classification not in valid_classifications:
                            invalid_tag_values.append({
                                'tag_name': 'DataClassification',
                                'current_value': key_tags['DataClassification'],
                                'valid_values': valid_classifications
                            })
                    
                    if 'ComplianceFramework' in key_tags:
                        framework = key_tags['ComplianceFramework'].upper()
                        if framework not in valid_frameworks:
                            invalid_tag_values.append({
                                'tag_name': 'ComplianceFramework',
                                'current_value': key_tags['ComplianceFramework'],
                                'valid_values': valid_frameworks
                            })
                    
                    # Check data residency matches current region
                    if 'DataResidency' in key_tags:
                        residency_region = key_tags['DataResidency']
                        if residency_region != region_name:
                            tag_violations.append({
                                'violation_type': 'residency_mismatch',
                                'description': f'DataResidency tag ({residency_region}) does not match current region ({region_name})',
                                'current_region': region_name,
                                'tagged_residency': residency_region
                            })
                    
                    # Check jurisdiction-specific requirements
                    if 'DataJurisdiction' in key_tags:
                        jurisdiction = key_tags['DataJurisdiction'].upper()
                        if jurisdiction in jurisdiction_specific_tags:
                            for required_tag in jurisdiction_specific_tags[jurisdiction]:
                                if required_tag not in key_tags:
                                    tag_violations.append({
                                        'violation_type': 'missing_jurisdiction_tag',
                                        'tag_name': required_tag,
                                        'jurisdiction': jurisdiction,
                                        'description': f'{required_tag} is required for {jurisdiction} jurisdiction'
                                    })
                    
                    # Validate optional tags if present
                    if 'SovereigntyLevel' in key_tags:
                        sovereignty_level = key_tags['SovereigntyLevel'].upper()
                        if sovereignty_level not in valid_sovereignty_levels:
                            invalid_tag_values.append({
                                'tag_name': 'SovereigntyLevel',
                                'current_value': key_tags['SovereigntyLevel'],
                                'valid_values': valid_sovereignty_levels
                            })
                    
                    if 'CrossBorderTransfer' in key_tags:
                        transfer_option = key_tags['CrossBorderTransfer'].upper()
                        if transfer_option not in valid_transfer_options:
                            invalid_tag_values.append({
                                'tag_name': 'CrossBorderTransfer',
                                'current_value': key_tags['CrossBorderTransfer'],
                                'valid_values': valid_transfer_options
                            })
                    
                    if 'LegalBasis' in key_tags:
                        legal_basis = key_tags['LegalBasis'].upper()
                        if legal_basis not in valid_legal_basis:
                            invalid_tag_values.append({
                                'tag_name': 'LegalBasis',
                                'current_value': key_tags['LegalBasis'],
                                'valid_values': valid_legal_basis
                            })
                    
                    if 'DataSubject' in key_tags:
                        data_subject = key_tags['DataSubject'].upper()
                        if data_subject not in valid_data_subjects:
                            invalid_tag_values.append({
                                'tag_name': 'DataSubject',
                                'current_value': key_tags['DataSubject'],
                                'valid_values': valid_data_subjects
                            })
                    
                    # Validate email format for compliance officer fields
                    email_fields = ['ComplianceOfficer', 'PrivacyOfficer', 'DataGovernor']
                    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
                    
                    for field in email_fields:
                        if field in key_tags:
                            email = key_tags[field]
                            if not re.match(email_pattern, email):
                                tag_violations.append({
                                    'violation_type': 'invalid_email_format',
                                    'tag_name': field,
                                    'current_value': email,
                                    'description': f'{field} must be a valid email address'
                                })
                    
                    # Validate retention period format (ISO 8601 duration)
                    if 'RetentionPeriod' in key_tags:
                        retention_period = key_tags['RetentionPeriod']
                        iso_duration_pattern = r'^P(?:(\d+)Y)?(?:(\d+)M)?(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?$'
                        if not re.match(iso_duration_pattern, retention_period):
                            tag_violations.append({
                                'violation_type': 'invalid_retention_format',
                                'tag_name': 'RetentionPeriod',
                                'current_value': retention_period,
                                'description': 'RetentionPeriod must be in ISO 8601 duration format (e.g., P7Y, P30D, PT24H)'
                            })
                    
                    # Check for classification and sovereignty level consistency
                    if 'DataClassification' in key_tags and 'SovereigntyLevel' in key_tags:
                        classification = key_tags['DataClassification'].upper()
                        sovereignty_level = key_tags['SovereigntyLevel'].upper()
                        
                        # High sensitivity data should have strict sovereignty
                        if classification in ['CONFIDENTIAL', 'RESTRICTED'] and sovereignty_level == 'FLEXIBLE':
                            tag_violations.append({
                                'violation_type': 'classification_sovereignty_mismatch',
                                'description': f'{classification} data classification requires STRICT or MODERATE sovereignty level, not {sovereignty_level}',
                                'data_classification': classification,
                                'sovereignty_level': sovereignty_level
                            })
                    
                    # Check for classification and cross-border transfer consistency
                    if 'DataClassification' in key_tags and 'CrossBorderTransfer' in key_tags:
                        classification = key_tags['DataClassification'].upper()
                        transfer_option = key_tags['CrossBorderTransfer'].upper()
                        
                        # Restricted data should not allow unrestricted transfers
                        if classification == 'RESTRICTED' and transfer_option == 'ALLOWED':
                            tag_violations.append({
                                'violation_type': 'classification_transfer_mismatch',
                                'description': f'RESTRICTED data classification should not allow unrestricted cross-border transfers',
                                'data_classification': classification,
                                'cross_border_transfer': transfer_option
                            })
                    
                    # Calculate tag completeness
                    total_possible_tags = len(required_base_tags) + 8  # 8 additional optional sovereignty tags
                    if 'DataJurisdiction' in key_tags:
                        jurisdiction = key_tags['DataJurisdiction'].upper()
                        if jurisdiction in jurisdiction_specific_tags:
                            total_possible_tags += len(jurisdiction_specific_tags[jurisdiction])
                    
                    present_tags = len([tag for tag in key_tags.keys() if tag in required_base_tags or tag in [
                        'SovereigntyLevel', 'CrossBorderTransfer', 'DataController', 'LegalBasis',
                        'DataProcessor', 'RetentionPeriod', 'DataSubject', 'ComplianceOfficer',
                        'PrivacyOfficer', 'DataGovernor'
                    ]])
                    
                    tag_completeness_percentage = (present_tags / total_possible_tags) * 100 if total_possible_tags > 0 else 0
                    
                    # Determine compliance status
                    is_compliant = (
                        len(missing_required_tags) == 0 and 
                        len(invalid_tag_values) == 0 and 
                        len(tag_violations) == 0
                    )
                    
                    # Create finding
                    finding = {
                        "region": region_name,
                        "profile": profile_name or "default",
                        "resource_type": "kms_key",
                        "resource_id": key_arn,
                        "status": "COMPLIANT" if is_compliant else "NON_COMPLIANT",
                        "risk_level": "MEDIUM" if not is_compliant else "LOW",
                        "recommendation": "KMS key has proper data sovereignty tags" if is_compliant else "Add or correct data sovereignty tags for KMS key",
                        "details": {
                            "key_id": key_id,
                            "key_arn": key_arn,
                            "key_manager": key_manager,
                            "key_usage": key_usage,
                            "key_state": key_state,
                            "key_spec": key_spec,
                            "sovereignty_tags": sovereignty_tags,
                            "all_tags": key_tags,
                            "tag_completeness_percentage": round(tag_completeness_percentage, 2),
                            "missing_required_tags": missing_required_tags,
                            "invalid_tag_values": invalid_tag_values,
                            "tag_violations": tag_violations,
                            "tag_compliance_checks": {
                                "has_required_tags": len(missing_required_tags) == 0,
                                "has_valid_values": len(invalid_tag_values) == 0,
                                "passes_validation": len(tag_violations) == 0,
                                "residency_matches_region": 'DataResidency' in key_tags and key_tags['DataResidency'] == region_name
                            }
                        }
                    }
                    
                    findings.append(finding)
                    
                except ClientError as e:
                    if e.response['Error']['Code'] in ['NotFoundException', 'KMSInvalidStateException']:
                        logger.warning(f"Key {key_id} not found or in invalid state: {e}")
                        continue
                    else:
                        logger.error(f"Error processing key {key_id}: {e}")
                        findings.append({
                            "region": region_name,
                            "profile": profile_name or "default",
                            "resource_type": "kms_key",
                            "resource_id": key_arn,
                            "status": "ERROR",
                            "risk_level": "MEDIUM",
                            "recommendation": "Fix API access issues for KMS key",
                            "details": {
                                "key_id": key_id,
                                "key_arn": key_arn,
                                "error": str(e)
                            }
                        })
                
                except Exception as e:
                    logger.error(f"Unexpected error processing key {key_id}: {e}")
                    findings.append({
                        "region": region_name,
                        "profile": profile_name or "default",
                        "resource_type": "kms_key",
                        "resource_id": key_arn,
                        "status": "ERROR",
                        "risk_level": "MEDIUM",
                        "recommendation": "Fix unexpected error in key processing",
                        "details": {
                            "key_id": key_id,
                            "key_arn": key_arn,
                            "error": str(e)
                        }
                    })
        
        logger.info(f"Completed checking kms_key_data_sovereignty_tags. Found {len(findings)} findings.")
        
    except NoCredentialsError:
        logger.error("AWS credentials not found")
        findings.append({
            "region": region_name,
            "profile": profile_name or "default",
            "resource_type": "kms_key",
            "resource_id": "unknown",
            "status": "ERROR",
            "risk_level": "HIGH",
            "recommendation": "Configure AWS credentials",
            "details": {
                "error": "AWS credentials not found"
            }
        })
        
    except ClientError as e:
        logger.error(f"AWS API error: {e}")
        findings.append({
            "region": region_name,
            "profile": profile_name or "default",
            "resource_type": "kms_key",
            "resource_id": "unknown",
            "status": "ERROR",
            "risk_level": "HIGH",
            "recommendation": "Fix AWS API access issues",
            "details": {
                "error": str(e),
                "error_code": e.response.get('Error', {}).get('Code', 'Unknown')
            }
        })
        
    except Exception as e:
        logger.error(f"Failed to check kms_key_data_sovereignty_tags: {e}")
        findings.append({
            "region": region_name,
            "profile": profile_name or "default",
            "resource_type": "kms_key",
            "resource_id": "unknown",
            "status": "ERROR",
            "risk_level": "HIGH",
            "recommendation": "Fix unexpected error in function execution",
            "details": {
                "error": str(e)
            }
        })
    
    return findings

def kms_key_data_sovereignty_tags(region_name: str, profile_name: str = None) -> Dict[str, Any]:
    """
    Main function wrapper for kms_key_data_sovereignty_tags.
    
    Args:
        region_name (str): AWS region name
        profile_name (str): AWS profile name (optional)
        
    Returns:
        Dict: Results summary
    """
    COMPLIANCE_DATA = load_rule_metadata("kms_key_data_sovereignty_tags")
    
    # TODO: Implement SecurityEngine integration when available
    # from data_security_engine import SecurityEngine
    # engine = SecurityEngine(COMPLIANCE_DATA)
    # return engine.run_check(region_name, profile_name, kms_key_data_sovereignty_tags_check)
    
    # Current implementation
    findings = kms_key_data_sovereignty_tags_check(region_name, profile_name)
    
    # Calculate compliance statistics
    total_findings = len(findings)
    compliant_findings = len([f for f in findings if f['status'] == 'COMPLIANT'])
    non_compliant_findings = len([f for f in findings if f['status'] == 'NON_COMPLIANT'])
    error_findings = len([f for f in findings if f['status'] == 'ERROR'])
    
    return {
        "function_name": "kms_key_data_sovereignty_tags",
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
    """CLI entry point for kms_key_data_sovereignty_tags."""
    # TODO: Implement setup_command_line_interface() when data_security_engine is available
    # from data_security_engine import setup_command_line_interface, save_results, exit_with_status
    # args = setup_command_line_interface()
    # results = kms_key_data_sovereignty_tags(args.region, args.profile)
    # save_results(results, args.output_file)
    # exit_with_status(results)
    
    # Current CLI implementation
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Ensure KMS keys are tagged with data sovereignty and jurisdiction information for compliance tracking."
    )
    parser.add_argument("--region", default="us-east-1", help="AWS region")
    parser.add_argument("--profile", help="AWS profile name")
    parser.add_argument("--output", help="Output file for results (JSON format)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        results = kms_key_data_sovereignty_tags(args.region, args.profile)
        
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

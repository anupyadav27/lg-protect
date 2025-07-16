#!/usr/bin/env python3
"""
data_security_aws - s3_bucket_data_sovereignty_tags

Ensure S3 buckets are tagged with data sovereignty and jurisdiction information for compliance tracking and regulatory auditing.
"""

# Rule Metadata from YAML:
# Function Name: s3_bucket_data_sovereignty_tags
# Capability: DATA_RESIDENCY
# Service: S3
# Subservice: TAGGING
# Description: Ensure S3 buckets are tagged with data sovereignty and jurisdiction information for compliance tracking and regulatory auditing.
# Risk Level: LOW
# Recommendation: Tag buckets with data sovereignty information
# API Function: client = boto3.client('s3')
# User Function: s3_bucket_data_sovereignty_tags()

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
        "function_name": "s3_bucket_data_sovereignty_tags",
        "title": "Tag buckets with data sovereignty information",
        "description": "Ensure S3 buckets are tagged with data sovereignty and jurisdiction information for compliance tracking and regulatory auditing.",
        "capability": "data_residency",
        "service": "s3",
        "subservice": "tagging",
        "risk": "LOW",
        "existing": False
    }

def s3_bucket_data_sovereignty_tags_check(region_name: str, profile_name: str = None) -> List[Dict[str, Any]]:
    """
    Check S3 buckets for data sovereignty tagging compliance.
    
    Args:
        region_name (str): AWS region name
        profile_name (str): AWS profile name (optional)
        
    Returns:
        List[Dict]: List of compliance findings
    """
    findings = []
    
    # Required data sovereignty tags
    REQUIRED_SOVEREIGNTY_TAGS = {
        'DataSovereignty': ['US', 'EU', 'UK', 'CA', 'AU', 'JP', 'APAC', 'GLOBAL'],
        'DataJurisdiction': ['US', 'EU', 'UK', 'CANADA', 'AUSTRALIA', 'JAPAN', 'SINGAPORE', 'GLOBAL'],
        'DataClassification': ['PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'RESTRICTED', 'TOP_SECRET'],
        'DataResidency': ['US_EAST_1', 'US_WEST_2', 'EU_WEST_1', 'EU_CENTRAL_1', 'AP_SOUTHEAST_1', 'AP_NORTHEAST_1']
    }
    
    # Optional but recommended tags
    RECOMMENDED_TAGS = [
        'DataOwner', 'BusinessUnit', 'CostCenter', 'Environment', 
        'Project', 'ComplianceFramework', 'RetentionPeriod'
    ]
    
    try:
        # Initialize boto3 client
        session = boto3.Session(profile_name=profile_name)
        s3_client = session.client('s3', region_name=region_name)
        
        logger.info(f"Checking S3 buckets for data sovereignty tagging compliance in region {region_name}")
        
        # Get all S3 buckets (this is a global operation)
        response = s3_client.list_buckets()
        buckets = response.get('Buckets', [])
        
        for bucket in buckets:
            bucket_name = bucket.get('Name')
            creation_date = bucket.get('CreationDate')
            
            try:
                # Get bucket region to verify residency compliance
                bucket_location = s3_client.get_bucket_location(Bucket=bucket_name)
                bucket_region = bucket_location.get('LocationConstraint')
                
                # Handle default region (us-east-1 returns None)
                if bucket_region is None:
                    bucket_region = 'us-east-1'
                
                # Get bucket tags
                try:
                    tags_response = s3_client.get_bucket_tagging(Bucket=bucket_name)
                    tags = tags_response.get('TagSet', [])
                    tag_dict = {tag.get('Key'): tag.get('Value') for tag in tags}
                except s3_client.exceptions.ClientError as tag_error:
                    if tag_error.response['Error']['Code'] == 'NoSuchTagSet':
                        tag_dict = {}
                    else:
                        raise tag_error
                
                # Check compliance violations
                tagging_violations = []
                compliance_features = []
                
                # Check required sovereignty tags
                missing_required_tags = []
                invalid_tag_values = []
                
                for required_tag, valid_values in REQUIRED_SOVEREIGNTY_TAGS.items():
                    tag_value = tag_dict.get(required_tag)
                    
                    if not tag_value:
                        missing_required_tags.append(required_tag)
                    elif tag_value.upper() not in [v.upper() for v in valid_values]:
                        invalid_tag_values.append({
                            'tag': required_tag,
                            'current_value': tag_value,
                            'valid_values': valid_values
                        })
                    else:
                        compliance_features.append({
                            'feature': f'{required_tag} Tag',
                            'value': tag_value,
                            'compliant': True
                        })
                
                if missing_required_tags:
                    tagging_violations.append(f"Missing required tags: {', '.join(missing_required_tags)}")
                
                if invalid_tag_values:
                    for invalid_tag in invalid_tag_values:
                        tagging_violations.append(
                            f"Invalid value '{invalid_tag['current_value']}' for tag '{invalid_tag['tag']}'. "
                            f"Valid values: {', '.join(invalid_tag['valid_values'])}"
                        )
                
                # Check data residency alignment with bucket location
                data_residency = tag_dict.get('DataResidency', '').upper()
                if data_residency:
                    expected_region_mapping = {
                        'US_EAST_1': 'us-east-1',
                        'US_WEST_2': 'us-west-2',
                        'EU_WEST_1': 'eu-west-1',
                        'EU_CENTRAL_1': 'eu-central-1',
                        'AP_SOUTHEAST_1': 'ap-southeast-1',
                        'AP_NORTHEAST_1': 'ap-northeast-1'
                    }
                    
                    expected_region = expected_region_mapping.get(data_residency)
                    if expected_region and expected_region != bucket_region:
                        tagging_violations.append(
                            f"Data residency tag '{data_residency}' does not match bucket region '{bucket_region}'"
                        )
                    elif not expected_region:
                        tagging_violations.append(f"Unrecognized data residency value: {data_residency}")
                
                # Check jurisdiction alignment with sovereignty
                data_sovereignty = tag_dict.get('DataSovereignty', '').upper()
                data_jurisdiction = tag_dict.get('DataJurisdiction', '').upper()
                
                if data_sovereignty and data_jurisdiction:
                    # Define jurisdiction mappings for sovereignty
                    sovereignty_jurisdiction_mapping = {
                        'US': ['US'],
                        'EU': ['EU'],
                        'UK': ['UK'],
                        'CA': ['CANADA'],
                        'AU': ['AUSTRALIA'],
                        'JP': ['JAPAN'],
                        'APAC': ['SINGAPORE', 'JAPAN', 'AUSTRALIA'],
                        'GLOBAL': ['US', 'EU', 'UK', 'CANADA', 'AUSTRALIA', 'JAPAN', 'SINGAPORE', 'GLOBAL']
                    }
                    
                    valid_jurisdictions = sovereignty_jurisdiction_mapping.get(data_sovereignty, [])
                    if data_jurisdiction not in valid_jurisdictions:
                        tagging_violations.append(
                            f"Data jurisdiction '{data_jurisdiction}' is not valid for sovereignty '{data_sovereignty}'"
                        )
                
                # Check for recommended tags
                present_recommended_tags = []
                missing_recommended_tags = []
                
                for rec_tag in RECOMMENDED_TAGS:
                    if rec_tag in tag_dict:
                        present_recommended_tags.append({
                            'tag': rec_tag,
                            'value': tag_dict[rec_tag]
                        })
                    else:
                        missing_recommended_tags.append(rec_tag)
                
                if present_recommended_tags:
                    compliance_features.append({
                        'feature': 'Recommended Tags',
                        'tags': present_recommended_tags,
                        'count': len(present_recommended_tags)
                    })
                
                # Check for environment-specific tagging
                environment = tag_dict.get('Environment', '').upper()
                if environment in ['PRODUCTION', 'PROD']:
                    # Production buckets should have stricter tagging requirements
                    critical_prod_tags = ['DataOwner', 'BusinessUnit', 'ComplianceFramework']
                    missing_critical = [tag for tag in critical_prod_tags if tag not in tag_dict]
                    
                    if missing_critical:
                        tagging_violations.append(
                            f"Production bucket missing critical tags: {', '.join(missing_critical)}"
                        )
                    else:
                        compliance_features.append({
                            'feature': 'Production Environment Compliance',
                            'critical_tags_present': True
                        })
                
                # Check compliance framework specific requirements
                compliance_framework = tag_dict.get('ComplianceFramework', '').upper()
                if compliance_framework:
                    framework_requirements = {
                        'GDPR': ['DataOwner', 'RetentionPeriod', 'DataClassification'],
                        'HIPAA': ['DataClassification', 'DataOwner', 'BusinessUnit'],
                        'SOX': ['DataOwner', 'BusinessUnit', 'CostCenter'],
                        'PCI': ['DataClassification', 'Environment', 'DataOwner']
                    }
                    
                    required_for_framework = framework_requirements.get(compliance_framework, [])
                    missing_framework_tags = [tag for tag in required_for_framework if tag not in tag_dict]
                    
                    if missing_framework_tags:
                        tagging_violations.append(
                            f"Missing tags required for {compliance_framework}: {', '.join(missing_framework_tags)}"
                        )
                    else:
                        compliance_features.append({
                            'feature': f'{compliance_framework} Compliance',
                            'framework_compliant': True
                        })
                
                # Check tag consistency and format
                for tag_key, tag_value in tag_dict.items():
                    # Check for empty values
                    if not tag_value or tag_value.strip() == '':
                        tagging_violations.append(f"Tag '{tag_key}' has empty value")
                    
                    # Check for suspicious characters or formats
                    if len(tag_value) > 256:
                        tagging_violations.append(f"Tag '{tag_key}' value exceeds 256 characters")
                    
                    # Check for consistent naming conventions
                    if tag_key in REQUIRED_SOVEREIGNTY_TAGS and not tag_value.isupper():
                        # Sovereignty tags should be uppercase for consistency
                        compliance_features.append({
                            'feature': 'Tag Format Warning',
                            'message': f"Consider using uppercase for sovereignty tag '{tag_key}'"
                        })
                
                # Calculate compliance score
                compliance_score = len(compliance_features)
                violation_count = len(tagging_violations)
                tag_coverage = len(tag_dict) / (len(REQUIRED_SOVEREIGNTY_TAGS) + len(RECOMMENDED_TAGS)) * 100
                
                # Determine compliance status
                critical_violations = len(missing_required_tags) + len(invalid_tag_values)
                
                if critical_violations > 0 or violation_count > compliance_score:
                    findings.append({
                        "region": region_name,
                        "profile": profile_name or "default",
                        "resource_type": "s3_bucket",
                        "resource_id": f"arn:aws:s3:::{bucket_name}",
                        "status": "NON_COMPLIANT",
                        "risk_level": "LOW",
                        "recommendation": "Add required data sovereignty tags to S3 bucket",
                        "details": {
                            "bucket_name": bucket_name,
                            "bucket_region": bucket_region,
                            "violation": f"Bucket has {violation_count} tagging violations",
                            "tagging_violations": tagging_violations,
                            "missing_required_tags": missing_required_tags,
                            "invalid_tag_values": invalid_tag_values,
                            "present_tags": tag_dict,
                            "compliance_features": compliance_features,
                            "compliance_score": compliance_score,
                            "tag_coverage_percent": round(tag_coverage, 2),
                            "creation_date": creation_date.isoformat() if creation_date else None
                        }
                    })
                else:
                    findings.append({
                        "region": region_name,
                        "profile": profile_name or "default",
                        "resource_type": "s3_bucket",
                        "resource_id": f"arn:aws:s3:::{bucket_name}",
                        "status": "COMPLIANT",
                        "risk_level": "LOW",
                        "recommendation": "S3 bucket has proper data sovereignty tagging",
                        "details": {
                            "bucket_name": bucket_name,
                            "bucket_region": bucket_region,
                            "present_tags": tag_dict,
                            "compliance_features": compliance_features,
                            "compliance_score": compliance_score,
                            "tag_coverage_percent": round(tag_coverage, 2),
                            "minor_issues": tagging_violations if tagging_violations else None,
                            "recommended_missing_tags": missing_recommended_tags,
                            "creation_date": creation_date.isoformat() if creation_date else None
                        }
                    })
                    
            except Exception as bucket_error:
                logger.warning(f"Failed to check bucket {bucket_name}: {bucket_error}")
                findings.append({
                    "region": region_name,
                    "profile": profile_name or "default",
                    "resource_type": "s3_bucket",
                    "resource_id": f"arn:aws:s3:::{bucket_name}",
                    "status": "ERROR",
                    "risk_level": "LOW",
                    "recommendation": "Unable to check S3 bucket tagging",
                    "details": {
                        "bucket_name": bucket_name,
                        "error": str(bucket_error)
                    }
                })
        
        logger.info(f"Completed checking s3_bucket_data_sovereignty_tags. Found {len(findings)} findings.")
        
    except Exception as e:
        logger.error(f"Failed to check s3_bucket_data_sovereignty_tags: {e}")
        findings.append({
            "region": region_name,
            "profile": profile_name or "default",
            "resource_type": "s3_bucket",
            "resource_id": "unknown",
            "status": "ERROR",
            "risk_level": "LOW",
            "recommendation": "Fix API access issues",
            "details": {
                "error": str(e)
            }
        })
    
    return findings

def s3_bucket_data_sovereignty_tags(region_name: str, profile_name: str = None) -> Dict[str, Any]:
    """
    Main function wrapper for s3_bucket_data_sovereignty_tags.
    
    Args:
        region_name (str): AWS region name
        profile_name (str): AWS profile name (optional)
        
    Returns:
        Dict: Results summary
    """
    COMPLIANCE_DATA = load_rule_metadata("s3_bucket_data_sovereignty_tags")
    
    # TODO: Implement SecurityEngine integration when available
    # from data_security_engine import SecurityEngine
    # engine = SecurityEngine(COMPLIANCE_DATA)
    # return engine.run_check(region_name, profile_name, s3_bucket_data_sovereignty_tags_check)
    
    # Current implementation
    findings = s3_bucket_data_sovereignty_tags_check(region_name, profile_name)
    
    # Calculate compliance statistics
    total_findings = len(findings)
    compliant_findings = len([f for f in findings if f['status'] == 'COMPLIANT'])
    non_compliant_findings = len([f for f in findings if f['status'] == 'NON_COMPLIANT'])
    error_findings = len([f for f in findings if f['status'] == 'ERROR'])
    
    return {
        "function_name": "s3_bucket_data_sovereignty_tags",
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
    """CLI entry point for s3_bucket_data_sovereignty_tags."""
    # TODO: Implement setup_command_line_interface() when data_security_engine is available
    # from data_security_engine import setup_command_line_interface, save_results, exit_with_status
    # args = setup_command_line_interface()
    # results = s3_bucket_data_sovereignty_tags(args.region, args.profile)
    # save_results(results, args.output_file)
    # exit_with_status(results)
    
    # Current CLI implementation
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Ensure S3 buckets are tagged with data sovereignty and jurisdiction information for compliance tracking and regulatory auditing."
    )
    parser.add_argument("--region", default="us-east-1", help="AWS region")
    parser.add_argument("--profile", help="AWS profile name")
    parser.add_argument("--output", help="Output file for results (JSON format)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        results = s3_bucket_data_sovereignty_tags(args.region, args.profile)
        
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

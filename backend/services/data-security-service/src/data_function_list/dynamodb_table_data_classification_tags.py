#!/usr/bin/env python3
"""
data_security_aws - dynamodb_table_data_classification_tags

Ensure DynamoDB tables are tagged with appropriate data classification levels for governance and compliance tracking.
"""

# Rule Metadata from YAML:
# Function Name: dynamodb_table_data_classification_tags
# Capability: DATA_PROTECTION
# Service: DYNAMODB
# Subservice: TAGGING
# Description: Ensure DynamoDB tables are tagged with appropriate data classification levels for governance and compliance tracking.
# Risk Level: LOW
# Recommendation: Tag DynamoDB tables with data classification
# API Function: client = boto3.client('dynamodb')
# User Function: dynamodb_table_data_classification_tags()

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
        "function_name": "dynamodb_table_data_classification_tags",
        "title": "Tag DynamoDB tables with data classification",
        "description": "Ensure DynamoDB tables are tagged with appropriate data classification levels for governance and compliance tracking.",
        "capability": "data_protection",
        "service": "dynamodb",
        "subservice": "tagging",
        "risk": "LOW",
        "existing": False
    }

def dynamodb_table_data_classification_tags_check(region_name: str, profile_name: str = None) -> List[Dict[str, Any]]:
    """
    Check DynamoDB tables for data classification tagging compliance.
    
    Args:
        region_name (str): AWS region name
        profile_name (str): AWS profile name (optional)
        
    Returns:
        List[Dict]: List of compliance findings
    """
    findings = []
    
    # Required data classification tags
    REQUIRED_CLASSIFICATION_TAGS = {
        'DataClassification': ['PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'RESTRICTED', 'TOP_SECRET'],
        'DataSensitivity': ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
        'DataType': ['PII', 'PHI', 'FINANCIAL', 'OPERATIONAL', 'ANALYTICAL', 'GENERAL'],
        'ComplianceFramework': ['GDPR', 'HIPAA', 'PCI', 'SOX', 'FISMA', 'ISO27001', 'NONE']
    }
    
    # Optional but recommended tags
    RECOMMENDED_TAGS = [
        'DataOwner', 'BusinessUnit', 'CostCenter', 'Environment', 
        'Project', 'RetentionPeriod', 'DataSource', 'PurposeOfUse'
    ]
    
    try:
        # Initialize boto3 client
        session = boto3.Session(profile_name=profile_name)
        dynamodb_client = session.client('dynamodb', region_name=region_name)
        
        logger.info(f"Checking DynamoDB tables for data classification tagging compliance in region {region_name}")
        
        # Get all DynamoDB tables in the region
        try:
            tables_response = dynamodb_client.list_tables()
            table_names = tables_response.get('TableNames', [])
            
            # Handle pagination if needed
            while 'LastEvaluatedTableName' in tables_response:
                tables_response = dynamodb_client.list_tables(
                    ExclusiveStartTableName=tables_response['LastEvaluatedTableName']
                )
                table_names.extend(tables_response.get('TableNames', []))
            
        except Exception as list_error:
            logger.error(f"Failed to list DynamoDB tables: {list_error}")
            findings.append({
                "region": region_name,
                "profile": profile_name or "default",
                "resource_type": "dynamodb_table",
                "resource_id": "unknown",
                "status": "ERROR",
                "risk_level": "LOW",
                "recommendation": "Unable to list DynamoDB tables",
                "details": {
                    "error": str(list_error)
                }
            })
            return findings
        
        for table_name in table_names:
            try:
                # Get table description
                table_response = dynamodb_client.describe_table(TableName=table_name)
                table = table_response.get('Table', {})
                table_arn = table.get('TableArn')
                table_status = table.get('TableStatus')
                creation_date = table.get('CreationDateTime')
                billing_mode = table.get('BillingModeSummary', {}).get('BillingMode', 'PROVISIONED')
                
                # Skip tables that are not active
                if table_status != 'ACTIVE':
                    continue
                
                # Get table tags
                try:
                    tags_response = dynamodb_client.list_tags_of_resource(ResourceArn=table_arn)
                    tags = tags_response.get('Tags', [])
                    tag_dict = {tag.get('Key'): tag.get('Value') for tag in tags}
                except Exception as tag_error:
                    logger.warning(f"Failed to get tags for table {table_name}: {tag_error}")
                    tag_dict = {}
                
                # Check compliance violations
                tagging_violations = []
                compliance_features = []
                
                # Check required classification tags
                missing_required_tags = []
                invalid_tag_values = []
                
                for required_tag, valid_values in REQUIRED_CLASSIFICATION_TAGS.items():
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
                
                # Check data classification and sensitivity alignment
                data_classification = tag_dict.get('DataClassification', '').upper()
                data_sensitivity = tag_dict.get('DataSensitivity', '').upper()
                
                if data_classification and data_sensitivity:
                    # Define classification-sensitivity mappings
                    classification_sensitivity_mapping = {
                        'PUBLIC': ['LOW'],
                        'INTERNAL': ['LOW', 'MEDIUM'],
                        'CONFIDENTIAL': ['MEDIUM', 'HIGH'],
                        'RESTRICTED': ['HIGH', 'CRITICAL'],
                        'TOP_SECRET': ['CRITICAL']
                    }
                    
                    valid_sensitivities = classification_sensitivity_mapping.get(data_classification, [])
                    if data_sensitivity not in valid_sensitivities:
                        tagging_violations.append(
                            f"Data sensitivity '{data_sensitivity}' is not appropriate for classification '{data_classification}'. "
                            f"Valid sensitivities: {', '.join(valid_sensitivities)}"
                        )
                    else:
                        compliance_features.append({
                            'feature': 'Classification-Sensitivity Alignment',
                            'classification': data_classification,
                            'sensitivity': data_sensitivity,
                            'aligned': True
                        })
                
                # Check data type and compliance framework alignment
                data_type = tag_dict.get('DataType', '').upper()
                compliance_framework = tag_dict.get('ComplianceFramework', '').upper()
                
                if data_type and compliance_framework:
                    # Define data type compliance requirements
                    datatype_compliance_mapping = {
                        'PII': ['GDPR', 'FISMA', 'ISO27001'],
                        'PHI': ['HIPAA', 'GDPR'],
                        'FINANCIAL': ['PCI', 'SOX', 'GDPR'],
                        'OPERATIONAL': ['SOX', 'ISO27001'],
                        'ANALYTICAL': ['GDPR', 'ISO27001']
                    }
                    
                    required_frameworks = datatype_compliance_mapping.get(data_type, [])
                    if required_frameworks and compliance_framework not in required_frameworks and compliance_framework != 'NONE':
                        tagging_violations.append(
                            f"Data type '{data_type}' should follow compliance frameworks: {', '.join(required_frameworks)}. "
                            f"Current: {compliance_framework}"
                        )
                    elif compliance_framework in required_frameworks:
                        compliance_features.append({
                            'feature': 'Data Type-Compliance Alignment',
                            'data_type': data_type,
                            'compliance_framework': compliance_framework,
                            'aligned': True
                        })
                
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
                
                # Check environment-specific requirements
                environment = tag_dict.get('Environment', '').upper()
                if environment in ['PRODUCTION', 'PROD']:
                    # Production tables should have stricter requirements
                    critical_prod_tags = ['DataOwner', 'BusinessUnit', 'RetentionPeriod']
                    missing_critical = [tag for tag in critical_prod_tags if tag not in tag_dict]
                    
                    if missing_critical:
                        tagging_violations.append(
                            f"Production table missing critical tags: {', '.join(missing_critical)}"
                        )
                    else:
                        compliance_features.append({
                            'feature': 'Production Environment Compliance',
                            'critical_tags_present': True
                        })
                
                # Check compliance framework specific requirements
                if compliance_framework and compliance_framework != 'NONE':
                    framework_requirements = {
                        'GDPR': ['DataOwner', 'RetentionPeriod', 'PurposeOfUse'],
                        'HIPAA': ['DataOwner', 'BusinessUnit', 'RetentionPeriod'],
                        'PCI': ['DataOwner', 'Environment', 'BusinessUnit'],
                        'SOX': ['DataOwner', 'BusinessUnit', 'CostCenter'],
                        'FISMA': ['DataClassification', 'DataOwner', 'BusinessUnit'],
                        'ISO27001': ['DataOwner', 'DataClassification', 'BusinessUnit']
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
                
                # Check for sensitive data handling requirements
                if data_type in ['PII', 'PHI', 'FINANCIAL']:
                    sensitive_data_requirements = ['DataOwner', 'RetentionPeriod', 'ComplianceFramework']
                    missing_sensitive_reqs = [tag for tag in sensitive_data_requirements if tag not in tag_dict]
                    
                    if missing_sensitive_reqs:
                        tagging_violations.append(
                            f"Sensitive data table missing required tags: {', '.join(missing_sensitive_reqs)}"
                        )
                    else:
                        compliance_features.append({
                            'feature': 'Sensitive Data Compliance',
                            'data_type': data_type,
                            'requirements_met': True
                        })
                
                # Check tag consistency and format
                for tag_key, tag_value in tag_dict.items():
                    # Check for empty values
                    if not tag_value or tag_value.strip() == '':
                        tagging_violations.append(f"Tag '{tag_key}' has empty value")
                    
                    # Check for tag value length
                    if len(tag_value) > 256:
                        tagging_violations.append(f"Tag '{tag_key}' value exceeds 256 characters")
                
                # Check table-specific requirements based on billing mode
                if billing_mode == 'PAY_PER_REQUEST':
                    # On-demand tables might have different tagging requirements
                    compliance_features.append({
                        'feature': 'On-Demand Table',
                        'billing_mode': billing_mode
                    })
                
                # Check for encryption status and data classification alignment
                try:
                    table_description = dynamodb_client.describe_table(TableName=table_name)
                    sse_description = table_description.get('Table', {}).get('SSEDescription', {})
                    encryption_status = sse_description.get('Status', 'DISABLED')
                    
                    if data_classification in ['CONFIDENTIAL', 'RESTRICTED', 'TOP_SECRET']:
                        if encryption_status != 'ENABLED':
                            tagging_violations.append(
                                f"Table with classification '{data_classification}' must have encryption enabled"
                            )
                        else:
                            compliance_features.append({
                                'feature': 'Encryption Compliance',
                                'classification': data_classification,
                                'encryption_enabled': True
                            })
                except Exception as encryption_error:
                    logger.warning(f"Failed to check encryption for table {table_name}: {encryption_error}")
                
                # Calculate compliance score
                compliance_score = len(compliance_features)
                violation_count = len(tagging_violations)
                tag_coverage = len(tag_dict) / (len(REQUIRED_CLASSIFICATION_TAGS) + len(RECOMMENDED_TAGS)) * 100
                
                # Determine compliance status
                critical_violations = len(missing_required_tags) + len(invalid_tag_values)
                
                if critical_violations > 0 or violation_count > compliance_score:
                    findings.append({
                        "region": region_name,
                        "profile": profile_name or "default",
                        "resource_type": "dynamodb_table",
                        "resource_id": table_arn,
                        "status": "NON_COMPLIANT",
                        "risk_level": "LOW",
                        "recommendation": "Add required data classification tags to DynamoDB table",
                        "details": {
                            "table_name": table_name,
                            "table_arn": table_arn,
                            "table_status": table_status,
                            "billing_mode": billing_mode,
                            "violation": f"Table has {violation_count} tagging violations",
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
                        "resource_type": "dynamodb_table",
                        "resource_id": table_arn,
                        "status": "COMPLIANT",
                        "risk_level": "LOW",
                        "recommendation": "DynamoDB table has proper data classification tagging",
                        "details": {
                            "table_name": table_name,
                            "table_arn": table_arn,
                            "table_status": table_status,
                            "billing_mode": billing_mode,
                            "present_tags": tag_dict,
                            "compliance_features": compliance_features,
                            "compliance_score": compliance_score,
                            "tag_coverage_percent": round(tag_coverage, 2),
                            "minor_issues": tagging_violations if tagging_violations else None,
                            "recommended_missing_tags": missing_recommended_tags,
                            "creation_date": creation_date.isoformat() if creation_date else None
                        }
                    })
                    
            except Exception as table_error:
                logger.warning(f"Failed to check table {table_name}: {table_error}")
                findings.append({
                    "region": region_name,
                    "profile": profile_name or "default",
                    "resource_type": "dynamodb_table",
                    "resource_id": f"arn:aws:dynamodb:{region_name}:{table_name}",
                    "status": "ERROR",
                    "risk_level": "LOW",
                    "recommendation": "Unable to check DynamoDB table tagging",
                    "details": {
                        "table_name": table_name,
                        "error": str(table_error)
                    }
                })
        
        logger.info(f"Completed checking dynamodb_table_data_classification_tags. Found {len(findings)} findings.")
        
    except Exception as e:
        logger.error(f"Failed to check dynamodb_table_data_classification_tags: {e}")
        findings.append({
            "region": region_name,
            "profile": profile_name or "default",
            "resource_type": "dynamodb_table",
            "resource_id": "unknown",
            "status": "ERROR",
            "risk_level": "LOW",
            "recommendation": "Fix API access issues",
            "details": {
                "error": str(e)
            }
        })
    
    return findings

def dynamodb_table_data_classification_tags(region_name: str, profile_name: str = None) -> Dict[str, Any]:
    """
    Main function wrapper for dynamodb_table_data_classification_tags.
    
    Args:
        region_name (str): AWS region name
        profile_name (str): AWS profile name (optional)
        
    Returns:
        Dict: Results summary
    """
    COMPLIANCE_DATA = load_rule_metadata("dynamodb_table_data_classification_tags")
    
    # TODO: Implement SecurityEngine integration when available
    # from data_security_engine import SecurityEngine
    # engine = SecurityEngine(COMPLIANCE_DATA)
    # return engine.run_check(region_name, profile_name, dynamodb_table_data_classification_tags_check)
    
    # Current implementation
    findings = dynamodb_table_data_classification_tags_check(region_name, profile_name)
    
    # Calculate compliance statistics
    total_findings = len(findings)
    compliant_findings = len([f for f in findings if f['status'] == 'COMPLIANT'])
    non_compliant_findings = len([f for f in findings if f['status'] == 'NON_COMPLIANT'])
    error_findings = len([f for f in findings if f['status'] == 'ERROR'])
    
    return {
        "function_name": "dynamodb_table_data_classification_tags",
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
    """CLI entry point for dynamodb_table_data_classification_tags."""
    # TODO: Implement setup_command_line_interface() when data_security_engine is available
    # from data_security_engine import setup_command_line_interface, save_results, exit_with_status
    # args = setup_command_line_interface()
    # results = dynamodb_table_data_classification_tags(args.region, args.profile)
    # save_results(results, args.output_file)
    # exit_with_status(results)
    
    # Current CLI implementation
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Ensure DynamoDB tables are tagged with appropriate data classification levels for governance and compliance tracking."
    )
    parser.add_argument("--region", default="us-east-1", help="AWS region")
    parser.add_argument("--profile", help="AWS profile name")
    parser.add_argument("--output", help="Output file for results (JSON format)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        results = dynamodb_table_data_classification_tags(args.region, args.profile)
        
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

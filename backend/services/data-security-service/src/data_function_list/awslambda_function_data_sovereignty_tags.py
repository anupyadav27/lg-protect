#!/usr/bin/env python3
"""
data_security_aws - awslambda_function_data_sovereignty_tags

Ensure Lambda functions are tagged with data sovereignty and jurisdiction information for compliance tracking.
"""

# Rule Metadata from YAML:
# Function Name: awslambda_function_data_sovereignty_tags
# Capability: DATA_RESIDENCY
# Service: LAMBDA
# Subservice: TAGGING
# Description: Ensure Lambda functions are tagged with data sovereignty and jurisdiction information for compliance tracking.
# Risk Level: LOW
# Recommendation: Tag Lambda functions with data sovereignty information
# API Function: client = boto3.client('lambda')
# User Function: awslambda_function_data_sovereignty_tags()

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
        "function_name": "awslambda_function_data_sovereignty_tags",
        "title": "Tag Lambda functions with data sovereignty information",
        "description": "Ensure Lambda functions are tagged with data sovereignty and jurisdiction information for compliance tracking.",
        "capability": "data_residency",
        "service": "lambda",
        "subservice": "tagging",
        "risk": "LOW",
        "existing": False
    }

def awslambda_function_data_sovereignty_tags_check(region_name: str, profile_name: str = None) -> List[Dict[str, Any]]:
    """
    Check lambda resources for data_residency compliance.
    
    Args:
        region_name (str): AWS region name
        profile_name (str): AWS profile name (optional)
        
    Returns:
        List[Dict]: List of compliance findings
    """
    findings = []
    
    # Required data sovereignty tags for compliance
    required_sovereignty_tags = [
        'DataSovereignty',
        'DataJurisdiction', 
        'DataClassification',
        'DataResidency',
        'ComplianceRegion'
    ]
    
    try:
        # Initialize boto3 client
        session = boto3.Session(profile_name=profile_name)
        lambda_client = session.client('lambda', region_name=region_name)
        
        logger.info(f"Checking lambda resources for data_residency compliance in region {region_name}")
        
        # Get all Lambda functions in the region
        paginator = lambda_client.get_paginator('list_functions')
        
        for page in paginator.paginate():
            for function in page['Functions']:
                function_name = function.get('FunctionName')
                function_arn = function.get('FunctionArn')
                
                try:
                    # Get function tags
                    tags_response = lambda_client.list_tags(Resource=function_arn)
                    function_tags = tags_response.get('Tags', {})
                    
                    # Check for required data sovereignty tags
                    missing_tags = []
                    present_tags = []
                    
                    for required_tag in required_sovereignty_tags:
                        if required_tag not in function_tags:
                            missing_tags.append(required_tag)
                        else:
                            tag_value = function_tags[required_tag]
                            if not tag_value or tag_value.strip() == '':
                                missing_tags.append(f"{required_tag} (empty value)")
                            else:
                                present_tags.append({
                                    'key': required_tag,
                                    'value': tag_value
                                })
                    
                    # Validate data jurisdiction tag value if present
                    jurisdiction_compliance_issues = []
                    if 'DataJurisdiction' in function_tags:
                        jurisdiction_value = function_tags['DataJurisdiction'].upper()
                        valid_jurisdictions = ['US', 'EU', 'APAC', 'CA', 'UK', 'AU', 'JP', 'GLOBAL']
                        if jurisdiction_value not in valid_jurisdictions:
                            jurisdiction_compliance_issues.append(f"Invalid jurisdiction value: {jurisdiction_value}")
                    
                    # Validate data classification if present
                    classification_issues = []
                    if 'DataClassification' in function_tags:
                        classification_value = function_tags['DataClassification'].upper()
                        valid_classifications = ['PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'RESTRICTED']
                        if classification_value not in valid_classifications:
                            classification_issues.append(f"Invalid classification value: {classification_value}")
                    
                    # Determine compliance status
                    if missing_tags or jurisdiction_compliance_issues or classification_issues:
                        violation_details = []
                        if missing_tags:
                            violation_details.append(f"Missing required tags: {', '.join(missing_tags)}")
                        if jurisdiction_compliance_issues:
                            violation_details.extend(jurisdiction_compliance_issues)
                        if classification_issues:
                            violation_details.extend(classification_issues)
                        
                        findings.append({
                            "region": region_name,
                            "profile": profile_name or "default",
                            "resource_type": "lambda_function",
                            "resource_id": function_arn,
                            "status": "NON_COMPLIANT",
                            "risk_level": "LOW",
                            "recommendation": "Add required data sovereignty tags to Lambda function",
                            "details": {
                                "function_name": function_name,
                                "function_arn": function_arn,
                                "violation": "; ".join(violation_details),
                                "missing_tags": missing_tags,
                                "present_sovereignty_tags": present_tags,
                                "total_tags_count": len(function_tags),
                                "runtime": function.get('Runtime'),
                                "last_modified": function.get('LastModified')
                            }
                        })
                    else:
                        # All required tags are present and valid
                        findings.append({
                            "region": region_name,
                            "profile": profile_name or "default",
                            "resource_type": "lambda_function",
                            "resource_id": function_arn,
                            "status": "COMPLIANT",
                            "risk_level": "LOW",
                            "recommendation": "Lambda function has all required data sovereignty tags",
                            "details": {
                                "function_name": function_name,
                                "function_arn": function_arn,
                                "sovereignty_tags": present_tags,
                                "total_tags_count": len(function_tags),
                                "runtime": function.get('Runtime'),
                                "last_modified": function.get('LastModified')
                            }
                        })
                        
                except Exception as func_error:
                    logger.warning(f"Failed to check tags for function {function_name}: {func_error}")
                    findings.append({
                        "region": region_name,
                        "profile": profile_name or "default",
                        "resource_type": "lambda_function",
                        "resource_id": function_arn,
                        "status": "ERROR",
                        "risk_level": "LOW",
                        "recommendation": "Unable to check data sovereignty tags",
                        "details": {
                            "function_name": function_name,
                            "function_arn": function_arn,
                            "error": str(func_error)
                        }
                    })
        
        logger.info(f"Completed checking awslambda_function_data_sovereignty_tags. Found {len(findings)} findings.")
        
    except Exception as e:
        logger.error(f"Failed to check awslambda_function_data_sovereignty_tags: {e}")
        findings.append({
            "region": region_name,
            "profile": profile_name or "default",
            "resource_type": "lambda_function",
            "resource_id": "unknown",
            "status": "ERROR",
            "risk_level": "LOW",
            "recommendation": "Fix API access issues",
            "details": {
                "error": str(e)
            }
        })
    
    return findings

def awslambda_function_data_sovereignty_tags(region_name: str, profile_name: str = None) -> Dict[str, Any]:
    """
    Main function wrapper for awslambda_function_data_sovereignty_tags.
    
    Args:
        region_name (str): AWS region name
        profile_name (str): AWS profile name (optional)
        
    Returns:
        Dict: Results summary
    """
    COMPLIANCE_DATA = load_rule_metadata("awslambda_function_data_sovereignty_tags")
    
    # TODO: Implement SecurityEngine integration when available
    # from data_security_engine import SecurityEngine
    # engine = SecurityEngine(COMPLIANCE_DATA)
    # return engine.run_check(region_name, profile_name, awslambda_function_data_sovereignty_tags_check)
    
    # Current implementation
    findings = awslambda_function_data_sovereignty_tags_check(region_name, profile_name)
    
    # Calculate compliance statistics
    total_findings = len(findings)
    compliant_findings = len([f for f in findings if f['status'] == 'COMPLIANT'])
    non_compliant_findings = len([f for f in findings if f['status'] == 'NON_COMPLIANT'])
    error_findings = len([f for f in findings if f['status'] == 'ERROR'])
    
    return {
        "function_name": "awslambda_function_data_sovereignty_tags",
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
    """CLI entry point for awslambda_function_data_sovereignty_tags."""
    # TODO: Implement setup_command_line_interface() when data_security_engine is available
    # from data_security_engine import setup_command_line_interface, save_results, exit_with_status
    # args = setup_command_line_interface()
    # results = awslambda_function_data_sovereignty_tags(args.region, args.profile)
    # save_results(results, args.output_file)
    # exit_with_status(results)
    
    # Current CLI implementation
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Ensure Lambda functions are tagged with data sovereignty and jurisdiction information for compliance tracking."
    )
    parser.add_argument("--region", default="us-east-1", help="AWS region")
    parser.add_argument("--profile", help="AWS profile name")
    parser.add_argument("--output", help="Output file for results (JSON format)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        results = awslambda_function_data_sovereignty_tags(args.region, args.profile)
        
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

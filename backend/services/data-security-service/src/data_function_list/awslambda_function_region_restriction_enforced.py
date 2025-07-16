#!/usr/bin/env python3
"""
data_security_aws - awslambda_function_region_restriction_enforced

Ensure Lambda functions are deployed only in approved regions to comply with data residency requirements.
"""

# Rule Metadata from YAML:
# Function Name: awslambda_function_region_restriction_enforced
# Capability: DATA_RESIDENCY
# Service: LAMBDA
# Subservice: REGION
# Description: Ensure Lambda functions are deployed only in approved regions to comply with data residency requirements.
# Risk Level: HIGH
# Recommendation: Enforce region restrictions for Lambda functions
# API Function: client = boto3.client('lambda')
# User Function: awslambda_function_region_restriction_enforced()

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
        "function_name": "awslambda_function_region_restriction_enforced",
        "title": "Enforce region restrictions for Lambda functions",
        "description": "Ensure Lambda functions are deployed only in approved regions to comply with data residency requirements.",
        "capability": "data_residency",
        "service": "lambda",
        "subservice": "region",
        "risk": "HIGH",
        "existing": False
    }

def awslambda_function_region_restriction_enforced_check(region_name: str, profile_name: str = None) -> List[Dict[str, Any]]:
    """
    Check lambda resources for data_residency compliance.
    
    Args:
        region_name (str): AWS region name
        profile_name (str): AWS profile name (optional)
        
    Returns:
        List[Dict]: List of compliance findings
    """
    findings = []
    
    # Define approved regions for different compliance jurisdictions
    approved_regions = {
        'US': ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2'],
        'EU': ['eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-central-1', 'eu-north-1'],
        'APAC': ['ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1', 'ap-northeast-2', 'ap-south-1'],
        'CA': ['ca-central-1'],
        'UK': ['eu-west-2'],  # London
        'AU': ['ap-southeast-2'],  # Sydney
        'JP': ['ap-northeast-1']  # Tokyo
    }
    
    try:
        # Initialize boto3 client
        session = boto3.Session(profile_name=profile_name)
        lambda_client = session.client('lambda', region_name=region_name)
        
        logger.info(f"Checking lambda resources for data_residency compliance in region {region_name}")
        
        # Determine the compliance jurisdiction for the current region
        current_jurisdiction = None
        for jurisdiction, regions in approved_regions.items():
            if region_name in regions:
                current_jurisdiction = jurisdiction
                break
        
        if not current_jurisdiction:
            # Region is not in any approved jurisdiction
            findings.append({
                "region": region_name,
                "profile": profile_name or "default",
                "resource_type": "lambda_region",
                "resource_id": f"region:{region_name}",
                "status": "NON_COMPLIANT",
                "risk_level": "HIGH",
                "recommendation": "Lambda functions should not be deployed in non-approved regions",
                "details": {
                    "current_region": region_name,
                    "violation": f"Region {region_name} is not in any approved jurisdiction",
                    "approved_regions": approved_regions
                }
            })
            return findings
        
        # Get all Lambda functions in the region
        paginator = lambda_client.get_paginator('list_functions')
        
        for page in paginator.paginate():
            for function in page['Functions']:
                function_name = function.get('FunctionName')
                function_arn = function.get('FunctionArn')
                
                try:
                    # Get function configuration and tags
                    function_config = lambda_client.get_function(FunctionName=function_name)
                    config = function_config.get('Configuration', {})
                    
                    # Get function tags to check for compliance requirements
                    try:
                        tags_response = lambda_client.list_tags(Resource=function_arn)
                        function_tags = tags_response.get('Tags', {})
                    except Exception:
                        function_tags = {}
                    
                    region_violations = []
                    compliance_details = {
                        'function_name': function_name,
                        'function_arn': function_arn,
                        'current_region': region_name,
                        'current_jurisdiction': current_jurisdiction,
                        'region_compliance_checks': []
                    }
                    
                    # Check if function has data jurisdiction tags
                    data_jurisdiction = function_tags.get('DataJurisdiction', '').upper()
                    data_residency = function_tags.get('DataResidency', '').upper()
                    compliance_region = function_tags.get('ComplianceRegion', '').upper()
                    
                    # Validate jurisdiction compliance
                    if data_jurisdiction:
                        if data_jurisdiction != current_jurisdiction:
                            # Check if the tagged jurisdiction allows this region
                            if data_jurisdiction in approved_regions:
                                if region_name not in approved_regions[data_jurisdiction]:
                                    region_violations.append({
                                        'violation_type': 'jurisdiction_mismatch',
                                        'message': f"Function tagged for {data_jurisdiction} jurisdiction but deployed in {current_jurisdiction} region",
                                        'expected_regions': approved_regions[data_jurisdiction],
                                        'current_region': region_name
                                    })
                            else:
                                region_violations.append({
                                    'violation_type': 'invalid_jurisdiction',
                                    'message': f"Invalid data jurisdiction tag: {data_jurisdiction}",
                                    'valid_jurisdictions': list(approved_regions.keys())
                                })
                        
                        compliance_details['region_compliance_checks'].append({
                            'check': 'data_jurisdiction_tag',
                            'tagged_jurisdiction': data_jurisdiction,
                            'compliant': len([v for v in region_violations if v['violation_type'] == 'jurisdiction_mismatch']) == 0
                        })
                    
                    # Check specific region requirements
                    if data_residency:
                        # Extract region from data residency tag
                        residency_region = data_residency.lower().replace('_', '-')
                        if residency_region != region_name:
                            region_violations.append({
                                'violation_type': 'residency_mismatch',
                                'message': f"Function requires data residency in {data_residency} but deployed in {region_name}",
                                'required_region': residency_region,
                                'current_region': region_name
                            })
                        
                        compliance_details['region_compliance_checks'].append({
                            'check': 'data_residency_tag',
                            'required_region': residency_region,
                            'compliant': residency_region == region_name
                        })
                    
                    # Check compliance region tag
                    if compliance_region:
                        if compliance_region != region_name.upper():
                            region_violations.append({
                                'violation_type': 'compliance_region_mismatch',
                                'message': f"Function tagged for compliance in {compliance_region} but deployed in {region_name.upper()}",
                                'required_region': compliance_region,
                                'current_region': region_name.upper()
                            })
                        
                        compliance_details['region_compliance_checks'].append({
                            'check': 'compliance_region_tag',
                            'required_region': compliance_region,
                            'compliant': compliance_region == region_name.upper()
                        })
                    
                    # Check for cross-region dependencies
                    cross_region_dependencies = []
                    
                    # Check event source mappings for cross-region resources
                    try:
                        event_mappings = lambda_client.list_event_source_mappings(FunctionName=function_name)
                        for mapping in event_mappings.get('EventSourceMappings', []):
                            event_source_arn = mapping.get('EventSourceArn', '')
                            if ':' in event_source_arn:
                                arn_parts = event_source_arn.split(':')
                                if len(arn_parts) >= 4:
                                    source_region = arn_parts[3]
                                    if source_region != region_name:
                                        # Check if cross-region access is within same jurisdiction
                                        source_jurisdiction = None
                                        for juris, regions in approved_regions.items():
                                            if source_region in regions:
                                                source_jurisdiction = juris
                                                break
                                        
                                        if source_jurisdiction != current_jurisdiction:
                                            cross_region_dependencies.append({
                                                'type': 'event_source',
                                                'resource_arn': event_source_arn,
                                                'source_region': source_region,
                                                'source_jurisdiction': source_jurisdiction,
                                                'compliant': False
                                            })
                                        else:
                                            cross_region_dependencies.append({
                                                'type': 'event_source',
                                                'resource_arn': event_source_arn,
                                                'source_region': source_region,
                                                'source_jurisdiction': source_jurisdiction,
                                                'compliant': True
                                            })
                    except Exception as esm_error:
                        logger.warning(f"Failed to check event source mappings for {function_name}: {esm_error}")
                    
                    # Check destinations for cross-region configuration
                    destinations_config = config.get('DestinationConfig')
                    if destinations_config:
                        for dest_type in ['OnSuccess', 'OnFailure']:
                            destination = destinations_config.get(dest_type, {})
                            if destination.get('Destination'):
                                dest_arn = destination.get('Destination')
                                if ':' in dest_arn:
                                    arn_parts = dest_arn.split(':')
                                    if len(arn_parts) >= 4:
                                        dest_region = arn_parts[3]
                                        if dest_region != region_name:
                                            dest_jurisdiction = None
                                            for juris, regions in approved_regions.items():
                                                if dest_region in regions:
                                                    dest_jurisdiction = juris
                                                    break
                                            
                                            cross_region_dependencies.append({
                                                'type': f'destination_{dest_type.lower()}',
                                                'resource_arn': dest_arn,
                                                'destination_region': dest_region,
                                                'destination_jurisdiction': dest_jurisdiction,
                                                'compliant': dest_jurisdiction == current_jurisdiction
                                            })
                    
                    # Add cross-region dependency violations
                    for dependency in cross_region_dependencies:
                        if not dependency.get('compliant', True):
                            region_violations.append({
                                'violation_type': 'cross_region_dependency',
                                'message': f"Function has {dependency['type']} dependency in different jurisdiction",
                                'dependency': dependency
                            })
                    
                    compliance_details['cross_region_dependencies'] = cross_region_dependencies
                    compliance_details['tags'] = {
                        'data_jurisdiction': data_jurisdiction,
                        'data_residency': data_residency,
                        'compliance_region': compliance_region
                    }
                    
                    # Determine compliance status
                    if region_violations:
                        findings.append({
                            "region": region_name,
                            "profile": profile_name or "default",
                            "resource_type": "lambda_function",
                            "resource_id": function_arn,
                            "status": "NON_COMPLIANT",
                            "risk_level": "HIGH",
                            "recommendation": "Ensure Lambda function complies with region restrictions",
                            "details": {
                                **compliance_details,
                                "violation": f"Function has {len(region_violations)} region compliance violations",
                                "region_violations": region_violations,
                                "runtime": function.get('Runtime'),
                                "last_modified": function.get('LastModified')
                            }
                        })
                    else:
                        findings.append({
                            "region": region_name,
                            "profile": profile_name or "default",
                            "resource_type": "lambda_function",
                            "resource_id": function_arn,
                            "status": "COMPLIANT",
                            "risk_level": "HIGH",
                            "recommendation": "Lambda function complies with region restrictions",
                            "details": {
                                **compliance_details,
                                "runtime": function.get('Runtime'),
                                "last_modified": function.get('LastModified')
                            }
                        })
                        
                except Exception as func_error:
                    logger.warning(f"Failed to check function {function_name}: {func_error}")
                    findings.append({
                        "region": region_name,
                        "profile": profile_name or "default",
                        "resource_type": "lambda_function",
                        "resource_id": function_arn,
                        "status": "ERROR",
                        "risk_level": "HIGH",
                        "recommendation": "Unable to check region restriction compliance",
                        "details": {
                            "function_name": function_name,
                            "function_arn": function_arn,
                            "error": str(func_error)
                        }
                    })
        
        logger.info(f"Completed checking awslambda_function_region_restriction_enforced. Found {len(findings)} findings.")
        
    except Exception as e:
        logger.error(f"Failed to check awslambda_function_region_restriction_enforced: {e}")
        findings.append({
            "region": region_name,
            "profile": profile_name or "default",
            "resource_type": "lambda_function",
            "resource_id": "unknown",
            "status": "ERROR",
            "risk_level": "HIGH",
            "recommendation": "Fix API access issues",
            "details": {
                "error": str(e)
            }
        })
    
    return findings

def awslambda_function_region_restriction_enforced(region_name: str, profile_name: str = None) -> Dict[str, Any]:
    """
    Main function wrapper for awslambda_function_region_restriction_enforced.
    
    Args:
        region_name (str): AWS region name
        profile_name (str): AWS profile name (optional)
        
    Returns:
        Dict: Results summary
    """
    COMPLIANCE_DATA = load_rule_metadata("awslambda_function_region_restriction_enforced")
    
    # TODO: Implement SecurityEngine integration when available
    # from data_security_engine import SecurityEngine
    # engine = SecurityEngine(COMPLIANCE_DATA)
    # return engine.run_check(region_name, profile_name, awslambda_function_region_restriction_enforced_check)
    
    # Current implementation
    findings = awslambda_function_region_restriction_enforced_check(region_name, profile_name)
    
    # Calculate compliance statistics
    total_findings = len(findings)
    compliant_findings = len([f for f in findings if f['status'] == 'COMPLIANT'])
    non_compliant_findings = len([f for f in findings if f['status'] == 'NON_COMPLIANT'])
    error_findings = len([f for f in findings if f['status'] == 'ERROR'])
    
    return {
        "function_name": "awslambda_function_region_restriction_enforced",
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
    """CLI entry point for awslambda_function_region_restriction_enforced."""
    # TODO: Implement setup_command_line_interface() when data_security_engine is available
    # from data_security_engine import setup_command_line_interface, save_results, exit_with_status
    # args = setup_command_line_interface()
    # results = awslambda_function_region_restriction_enforced(args.region, args.profile)
    # save_results(results, args.output_file)
    # exit_with_status(results)
    
    # Current CLI implementation
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Ensure Lambda functions are deployed only in approved regions to comply with data residency requirements."
    )
    parser.add_argument("--region", default="us-east-1", help="AWS region")
    parser.add_argument("--profile", help="AWS profile name")
    parser.add_argument("--output", help="Output file for results (JSON format)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        results = awslambda_function_region_restriction_enforced(args.region, args.profile)
        
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

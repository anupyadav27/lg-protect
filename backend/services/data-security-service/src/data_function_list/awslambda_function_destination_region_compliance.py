#!/usr/bin/env python3
"""
data_security_aws - awslambda_function_destination_region_compliance

Ensure Lambda function destinations are configured only in regions that meet data residency requirements.
"""

# Rule Metadata from YAML:
# Function Name: awslambda_function_destination_region_compliance
# Capability: DATA_RESIDENCY
# Service: LAMBDA
# Subservice: DESTINATIONS
# Description: Ensure Lambda function destinations are configured only in regions that meet data residency requirements.
# Risk Level: MEDIUM
# Recommendation: Validate Lambda destination regions for compliance
# API Function: client = boto3.client('lambda')
# User Function: awslambda_function_destination_region_compliance()

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
        "function_name": "awslambda_function_destination_region_compliance",
        "title": "Validate Lambda destination regions for compliance",
        "description": "Ensure Lambda function destinations are configured only in regions that meet data residency requirements.",
        "capability": "data_residency",
        "service": "lambda",
        "subservice": "destinations",
        "risk": "MEDIUM",
        "existing": False
    }

def awslambda_function_destination_region_compliance_check(region_name: str, profile_name: str = None) -> List[Dict[str, Any]]:
    """
    Check lambda resources for data_residency compliance.
    
    Args:
        region_name (str): AWS region name
        profile_name (str): AWS profile name (optional)
        
    Returns:
        List[Dict]: List of compliance findings
    """
    findings = []
    
    # Define allowed regions for data residency compliance
    allowed_regions = {
        'US': ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2'],
        'EU': ['eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-central-1', 'eu-north-1'],
        'APAC': ['ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1', 'ap-northeast-2', 'ap-south-1']
    }
    
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
                    # Get function configuration to check event source mappings and destinations
                    function_config = lambda_client.get_function(FunctionName=function_name)
                    
                    # Check event source mappings for destination regions
                    try:
                        event_source_mappings = lambda_client.list_event_source_mappings(FunctionName=function_name)
                        esm_violations = []
                        
                        for mapping in event_source_mappings.get('EventSourceMappings', []):
                            event_source_arn = mapping.get('EventSourceArn', '')
                            
                            # Extract region from event source ARN
                            if ':' in event_source_arn:
                                arn_parts = event_source_arn.split(':')
                                if len(arn_parts) >= 4:
                                    source_region = arn_parts[3]
                                    
                                    # Check if source region is in allowed regions
                                    is_compliant_region = False
                                    for jurisdiction, regions in allowed_regions.items():
                                        if source_region in regions and region_name in regions:
                                            is_compliant_region = True
                                            break
                                    
                                    if not is_compliant_region:
                                        esm_violations.append({
                                            'event_source_arn': event_source_arn,
                                            'source_region': source_region,
                                            'mapping_uuid': mapping.get('UUID')
                                        })
                    except Exception as esm_error:
                        logger.warning(f"Failed to check event source mappings for {function_name}: {esm_error}")
                        esm_violations = []
                    
                    # Check function destinations configuration
                    destinations_config = function_config.get('Configuration', {}).get('DestinationConfig')
                    destination_violations = []
                    
                    if destinations_config:
                        # Check OnSuccess destinations
                        on_success = destinations_config.get('OnSuccess', {})
                        if on_success.get('Destination'):
                            dest_arn = on_success.get('Destination')
                            dest_region = _extract_region_from_arn(dest_arn)
                            if dest_region and not _is_region_compliant(dest_region, region_name, allowed_regions):
                                destination_violations.append({
                                    'type': 'OnSuccess',
                                    'destination_arn': dest_arn,
                                    'destination_region': dest_region
                                })
                        
                        # Check OnFailure destinations
                        on_failure = destinations_config.get('OnFailure', {})
                        if on_failure.get('Destination'):
                            dest_arn = on_failure.get('Destination')
                            dest_region = _extract_region_from_arn(dest_arn)
                            if dest_region and not _is_region_compliant(dest_region, region_name, allowed_regions):
                                destination_violations.append({
                                    'type': 'OnFailure',
                                    'destination_arn': dest_arn,
                                    'destination_region': dest_region
                                })
                    
                    # Determine compliance status
                    if esm_violations or destination_violations:
                        violation_details = []
                        if esm_violations:
                            violation_details.append(f"Event source mappings from non-compliant regions: {len(esm_violations)}")
                        if destination_violations:
                            violation_details.append(f"Destinations in non-compliant regions: {len(destination_violations)}")
                        
                        findings.append({
                            "region": region_name,
                            "profile": profile_name or "default",
                            "resource_type": "lambda_function",
                            "resource_id": function_arn,
                            "status": "NON_COMPLIANT",
                            "risk_level": "MEDIUM",
                            "recommendation": "Configure Lambda destinations and event sources only in compliant regions",
                            "details": {
                                "function_name": function_name,
                                "function_arn": function_arn,
                                "violation": "; ".join(violation_details),
                                "event_source_violations": esm_violations,
                                "destination_violations": destination_violations,
                                "function_region": region_name,
                                "runtime": function.get('Runtime'),
                                "last_modified": function.get('LastModified')
                            }
                        })
                    else:
                        # Check if function has any destinations configured
                        has_destinations = bool(destinations_config and (
                            destinations_config.get('OnSuccess', {}).get('Destination') or
                            destinations_config.get('OnFailure', {}).get('Destination')
                        ))
                        
                        findings.append({
                            "region": region_name,
                            "profile": profile_name or "default",
                            "resource_type": "lambda_function",
                            "resource_id": function_arn,
                            "status": "COMPLIANT",
                            "risk_level": "MEDIUM",
                            "recommendation": "Lambda function destinations comply with regional requirements",
                            "details": {
                                "function_name": function_name,
                                "function_arn": function_arn,
                                "has_destinations": has_destinations,
                                "event_source_mappings_count": len(event_source_mappings.get('EventSourceMappings', [])),
                                "function_region": region_name,
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
                        "risk_level": "MEDIUM",
                        "recommendation": "Unable to check destination region compliance",
                        "details": {
                            "function_name": function_name,
                            "function_arn": function_arn,
                            "error": str(func_error)
                        }
                    })
        
        logger.info(f"Completed checking awslambda_function_destination_region_compliance. Found {len(findings)} findings.")
        
    except Exception as e:
        logger.error(f"Failed to check awslambda_function_destination_region_compliance: {e}")
        findings.append({
            "region": region_name,
            "profile": profile_name or "default",
            "resource_type": "lambda_function",
            "resource_id": "unknown",
            "status": "ERROR",
            "risk_level": "MEDIUM",
            "recommendation": "Fix API access issues",
            "details": {
                "error": str(e)
            }
        })
    
    return findings

def _extract_region_from_arn(arn: str) -> str:
    """Extract region from AWS ARN."""
    if ':' in arn:
        arn_parts = arn.split(':')
        if len(arn_parts) >= 4:
            return arn_parts[3]
    return None

def _is_region_compliant(dest_region: str, function_region: str, allowed_regions: dict) -> bool:
    """Check if destination region is compliant with function region."""
    for jurisdiction, regions in allowed_regions.items():
        if function_region in regions and dest_region in regions:
            return True
    return False

def awslambda_function_destination_region_compliance(region_name: str, profile_name: str = None) -> Dict[str, Any]:
    """
    Main function wrapper for awslambda_function_destination_region_compliance.
    
    Args:
        region_name (str): AWS region name
        profile_name (str): AWS profile name (optional)
        
    Returns:
        Dict: Results summary
    """
    COMPLIANCE_DATA = load_rule_metadata("awslambda_function_destination_region_compliance")
    
    # TODO: Implement SecurityEngine integration when available
    # from data_security_engine import SecurityEngine
    # engine = SecurityEngine(COMPLIANCE_DATA)
    # return engine.run_check(region_name, profile_name, awslambda_function_destination_region_compliance_check)
    
    # Current implementation
    findings = awslambda_function_destination_region_compliance_check(region_name, profile_name)
    
    # Calculate compliance statistics
    total_findings = len(findings)
    compliant_findings = len([f for f in findings if f['status'] == 'COMPLIANT'])
    non_compliant_findings = len([f for f in findings if f['status'] == 'NON_COMPLIANT'])
    error_findings = len([f for f in findings if f['status'] == 'ERROR'])
    
    return {
        "function_name": "awslambda_function_destination_region_compliance",
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
    """CLI entry point for awslambda_function_destination_region_compliance."""
    # TODO: Implement setup_command_line_interface() when data_security_engine is available
    # from data_security_engine import setup_command_line_interface, save_results, exit_with_status
    # args = setup_command_line_interface()
    # results = awslambda_function_destination_region_compliance(args.region, args.profile)
    # save_results(results, args.output_file)
    # exit_with_status(results)
    
    # Current CLI implementation
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Ensure Lambda function destinations are configured only in regions that meet data residency requirements."
    )
    parser.add_argument("--region", default="us-east-1", help="AWS region")
    parser.add_argument("--profile", help="AWS profile name")
    parser.add_argument("--output", help="Output file for results (JSON format)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        results = awslambda_function_destination_region_compliance(args.region, args.profile)
        
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

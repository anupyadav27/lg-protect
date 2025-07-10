#!/usr/bin/env python3
"""
cis_4.0_aws - apigateway_restapi_waf_acl_attached

Ensure API Gateway REST API has WAF ACL attached
"""

import sys
import os
import json
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
        # Path to compliance_checks.json relative to functions_list directory
        compliance_json_path = os.path.join(
            os.path.dirname(__file__), 
            '..', '..', 
            'compliance_checks.json'
        )
        
        with open(compliance_json_path, 'r') as f:
            compliance_data = json.load(f)
        
        # Find the specific compliance entry for this function
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
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'cis_4.0_aws',
        'function_name': 'apigateway_restapi_waf_acl_attached',
        'id': 'api-gateway-waf',
        'name': 'API Gateway REST API WAF ACL',
        'description': 'Ensure API Gateway REST API has WAF ACL attached',
        'api_function': 'client1 = boto3.client(\'apigateway\'), client2 = boto3.client(\'wafv2\')',
        'user_function': 'get_rest_apis(), get_stages(), list_web_acls()',
        'risk_level': 'HIGH',
        'recommendation': 'Attach WAF ACL to protect API Gateway REST APIs'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('apigateway_restapi_waf_acl_attached')

def apigateway_restapi_waf_acl_attached_check(apigateway_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for apigateway_restapi_waf_acl_attached.
    
    Args:
        apigateway_client: Boto3 apigateway client (auto-created by framework)
        region (str): AWS region (auto-managed by framework)
        profile (str): AWS profile name (auto-managed by framework)
        logger: Logger instance (auto-configured by framework)
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    try:
        import boto3
        
        # Create WAFv2 client to check for web ACL associations
        try:
            wafv2_client = boto3.client('wafv2', region_name=region)
        except Exception as waf_client_error:
            logger.error(f"Could not create WAFv2 client: {waf_client_error}")
            wafv2_client = None
        
        # Get all REST APIs
        response = apigateway_client.get_rest_apis()
        rest_apis = response.get('items', [])
        
        if not rest_apis:
            # No REST APIs found - create a finding indicating no resources
            findings.append({
                'region': region,
                'profile': profile,
                'resource_type': 'AWS::ApiGateway::RestApi',
                'resource_id': 'No APIs found',
                'status': 'COMPLIANT',
                'compliance_status': 'PASS',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                'recommendation': COMPLIANCE_DATA.get('recommendation', 'Attach WAF ACL to protect API Gateway REST APIs'),
                'details': {
                    'message': 'No REST APIs found in this region'
                }
            })
            return findings
        
        for api in rest_apis:
            api_id = api.get('id')
            api_name = api.get('name', 'Unknown')
            
            try:
                # Get stages for this API
                stages_response = apigateway_client.get_stages(restApiId=api_id)
                stages = stages_response.get('item', [])
                
                if not stages:
                    # API has no stages
                    findings.append({
                        'region': region,
                        'profile': profile,
                        'resource_type': 'AWS::ApiGateway::RestApi',
                        'resource_id': api_id,
                        'status': 'NON_COMPLIANT',
                        'compliance_status': 'FAIL',
                        'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                        'recommendation': COMPLIANCE_DATA.get('recommendation', 'Attach WAF ACL to protect API Gateway REST APIs'),
                        'details': {
                            'api_name': api_name,
                            'message': 'No stages found for this API'
                        }
                    })
                    continue
                
                # Check each stage for WAF association
                for stage in stages:
                    stage_name = stage.get('stageName')
                    web_acl_arn = stage.get('webAclArn')
                    
                    has_waf_acl = bool(web_acl_arn)
                    
                    # Additional check using WAFv2 client if available
                    waf_details = {}
                    if wafv2_client and has_waf_acl:
                        try:
                            # Try to get WAF ACL details
                            waf_details['web_acl_arn'] = web_acl_arn
                            # Extract web ACL ID from ARN for additional validation
                            if web_acl_arn:
                                acl_parts = web_acl_arn.split('/')
                                if len(acl_parts) >= 3:
                                    web_acl_id = acl_parts[-1]
                                    web_acl_name = acl_parts[-2]
                                    waf_details['web_acl_id'] = web_acl_id
                                    waf_details['web_acl_name'] = web_acl_name
                        except Exception as waf_error:
                            logger.warning(f"Could not validate WAF ACL details: {waf_error}")
                    
                    findings.append({
                        'region': region,
                        'profile': profile,
                        'resource_type': 'AWS::ApiGateway::Stage',
                        'resource_id': f"{api_id}/{stage_name}",
                        'status': 'COMPLIANT' if has_waf_acl else 'NON_COMPLIANT',
                        'compliance_status': 'PASS' if has_waf_acl else 'FAIL',
                        'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                        'recommendation': COMPLIANCE_DATA.get('recommendation', 'Attach WAF ACL to protect API Gateway REST APIs'),
                        'details': {
                            'api_name': api_name,
                            'api_id': api_id,
                            'stage_name': stage_name,
                            'has_waf_acl': has_waf_acl,
                            'web_acl_arn': web_acl_arn,
                            'waf_details': waf_details
                        }
                    })
                    
            except Exception as stage_error:
                logger.error(f"Error checking stages for API {api_id}: {stage_error}")
                findings.append({
                    'region': region,
                    'profile': profile,
                    'resource_type': 'AWS::ApiGateway::RestApi',
                    'resource_id': api_id,
                    'status': 'ERROR',
                    'compliance_status': 'ERROR',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Attach WAF ACL to protect API Gateway REST APIs'),
                    'error': str(stage_error),
                    'details': {
                        'api_name': api_name
                    }
                })
        
    except Exception as e:
        logger.error(f"Error in apigateway_restapi_waf_acl_attached check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'AWS::ApiGateway::RestApi',
            'resource_id': 'Unknown',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Attach WAF ACL to protect API Gateway REST APIs'),
            'error': str(e)
        })
        
    return findings

def apigateway_restapi_waf_acl_attached(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=apigateway_restapi_waf_acl_attached_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = apigateway_restapi_waf_acl_attached(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

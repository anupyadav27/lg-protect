#!/usr/bin/env python3
"""
data_security_aws - awslambda_function_layer_region_compliance

Ensure Lambda layers are shared only within approved regions to maintain data residency compliance.
"""

# Rule Metadata from YAML:
# Function Name: awslambda_function_layer_region_compliance
# Capability: DATA_RESIDENCY
# Service: LAMBDA
# Subservice: LAYERS
# Description: Ensure Lambda layers are shared only within approved regions to maintain data residency compliance.
# Risk Level: MEDIUM
# Recommendation: Ensure Lambda layers comply with region restrictions
# API Function: client = boto3.client('lambda')
# User Function: awslambda_function_layer_region_compliance()

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
        "function_name": "awslambda_function_layer_region_compliance",
        "title": "Ensure Lambda layers comply with region restrictions",
        "description": "Ensure Lambda layers are shared only within approved regions to maintain data residency compliance.",
        "capability": "data_residency",
        "service": "lambda",
        "subservice": "layers",
        "risk": "MEDIUM",
        "existing": False
    }

def awslambda_function_layer_region_compliance_check(region_name: str, profile_name: str = None) -> List[Dict[str, Any]]:
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
        
        # Check Lambda layers in the region
        try:
            layers_paginator = lambda_client.get_paginator('list_layers')
            
            for layer_page in layers_paginator.paginate():
                for layer in layer_page.get('Layers', []):
                    layer_name = layer.get('LayerName')
                    layer_arn = layer.get('LayerArn')
                    
                    try:
                        # Get layer versions to check for cross-region sharing
                        versions_response = lambda_client.list_layer_versions(LayerName=layer_name)
                        
                        region_violations = []
                        layer_details = {
                            'layer_name': layer_name,
                            'layer_arn': layer_arn,
                            'total_versions': len(versions_response.get('LayerVersions', [])),
                            'cross_region_permissions': []
                        }
                        
                        # Check each version for permissions
                        for version in versions_response.get('LayerVersions', []):
                            version_number = version.get('Version')
                            
                            try:
                                # Check layer permissions for this version
                                permissions_response = lambda_client.get_layer_version_policy(
                                    LayerName=layer_name,
                                    VersionNumber=version_number
                                )
                                
                                policy_document = json.loads(permissions_response.get('Policy', '{}'))
                                statements = policy_document.get('Statement', [])
                                
                                for statement in statements:
                                    # Check for cross-region access
                                    principals = statement.get('Principal', {})
                                    conditions = statement.get('Condition', {})
                                    
                                    # Look for region-specific conditions
                                    if 'StringEquals' in conditions:
                                        source_region = conditions['StringEquals'].get('AWS:SourceRegion')
                                        if source_region and source_region != region_name:
                                            # Check if the source region is in the same jurisdiction
                                            is_compliant = False
                                            for jurisdiction, regions in allowed_regions.items():
                                                if region_name in regions and source_region in regions:
                                                    is_compliant = True
                                                    break
                                            
                                            if not is_compliant:
                                                region_violations.append({
                                                    'version': version_number,
                                                    'source_region': source_region,
                                                    'statement_id': statement.get('Sid'),
                                                    'violation': f"Layer shared with non-compliant region: {source_region}"
                                                })
                                            
                                            layer_details['cross_region_permissions'].append({
                                                'version': version_number,
                                                'source_region': source_region,
                                                'compliant': is_compliant
                                            })
                                    
                                    # Check for wildcard principals that could allow cross-region access
                                    if isinstance(principals, str) and principals == '*':
                                        region_violations.append({
                                            'version': version_number,
                                            'violation': "Layer has wildcard principal allowing unrestricted access"
                                        })
                                    elif isinstance(principals, dict) and principals.get('AWS') == '*':
                                        region_violations.append({
                                            'version': version_number,
                                            'violation': "Layer has wildcard AWS principal allowing unrestricted access"
                                        })
                                
                            except lambda_client.exceptions.ResourceNotFoundException:
                                # No policy exists for this version - this is actually good for region compliance
                                continue
                            except Exception as perm_error:
                                logger.warning(f"Failed to check permissions for layer {layer_name} version {version_number}: {perm_error}")
                        
                        # Determine compliance status
                        if region_violations:
                            findings.append({
                                "region": region_name,
                                "profile": profile_name or "default",
                                "resource_type": "lambda_layer",
                                "resource_id": layer_arn,
                                "status": "NON_COMPLIANT",
                                "risk_level": "MEDIUM",
                                "recommendation": "Remove cross-region permissions that violate data residency requirements",
                                "details": {
                                    **layer_details,
                                    "violation": f"Layer has {len(region_violations)} region compliance violations",
                                    "region_violations": region_violations
                                }
                            })
                        else:
                            findings.append({
                                "region": region_name,
                                "profile": profile_name or "default",
                                "resource_type": "lambda_layer",
                                "resource_id": layer_arn,
                                "status": "COMPLIANT",
                                "risk_level": "MEDIUM",
                                "recommendation": "Lambda layer complies with region restrictions",
                                "details": layer_details
                            })
                            
                    except Exception as layer_error:
                        logger.warning(f"Failed to check layer {layer_name}: {layer_error}")
                        findings.append({
                            "region": region_name,
                            "profile": profile_name or "default",
                            "resource_type": "lambda_layer",
                            "resource_id": layer_arn or f"layer:{layer_name}",
                            "status": "ERROR",
                            "risk_level": "MEDIUM",
                            "recommendation": "Unable to check layer region compliance",
                            "details": {
                                "layer_name": layer_name,
                                "error": str(layer_error)
                            }
                        })
        except Exception as layers_error:
            logger.warning(f"Failed to list layers: {layers_error}")
        
        # Check Lambda functions and their layer usage
        functions_paginator = lambda_client.get_paginator('list_functions')
        
        for page in functions_paginator.paginate():
            for function in page['Functions']:
                function_name = function.get('FunctionName')
                function_arn = function.get('FunctionArn')
                
                try:
                    # Get function configuration to check layers
                    function_config = lambda_client.get_function(FunctionName=function_name)
                    config = function_config.get('Configuration', {})
                    
                    layers = config.get('Layers', [])
                    if not layers:
                        # Function has no layers - compliant by default
                        continue
                    
                    layer_violations = []
                    function_layer_details = {
                        'function_name': function_name,
                        'function_arn': function_arn,
                        'layers_count': len(layers),
                        'layer_analysis': []
                    }
                    
                    for layer in layers:
                        layer_arn = layer.get('Arn')
                        
                        # Extract region from layer ARN
                        if ':' in layer_arn:
                            arn_parts = layer_arn.split(':')
                            if len(arn_parts) >= 4:
                                layer_region = arn_parts[3]
                                
                                # Check if layer region is compliant
                                is_compliant = False
                                for jurisdiction, regions in allowed_regions.items():
                                    if region_name in regions and layer_region in regions:
                                        is_compliant = True
                                        break
                                
                                function_layer_details['layer_analysis'].append({
                                    'layer_arn': layer_arn,
                                    'layer_region': layer_region,
                                    'compliant': is_compliant
                                })
                                
                                if not is_compliant:
                                    layer_violations.append({
                                        'layer_arn': layer_arn,
                                        'layer_region': layer_region,
                                        'violation': f"Function uses layer from non-compliant region: {layer_region}"
                                    })
                    
                    # Only report findings if there are violations
                    if layer_violations:
                        findings.append({
                            "region": region_name,
                            "profile": profile_name or "default",
                            "resource_type": "lambda_function",
                            "resource_id": function_arn,
                            "status": "NON_COMPLIANT",
                            "risk_level": "MEDIUM",
                            "recommendation": "Use layers only from compliant regions",
                            "details": {
                                **function_layer_details,
                                "violation": f"Function uses {len(layer_violations)} layers from non-compliant regions",
                                "layer_violations": layer_violations,
                                "runtime": function.get('Runtime'),
                                "last_modified": function.get('LastModified')
                            }
                        })
                        
                except Exception as func_error:
                    logger.warning(f"Failed to check function {function_name} layers: {func_error}")
        
        logger.info(f"Completed checking awslambda_function_layer_region_compliance. Found {len(findings)} findings.")
        
    except Exception as e:
        logger.error(f"Failed to check awslambda_function_layer_region_compliance: {e}")
        findings.append({
            "region": region_name,
            "profile": profile_name or "default",
            "resource_type": "lambda_layer",
            "resource_id": "unknown",
            "status": "ERROR",
            "risk_level": "MEDIUM",
            "recommendation": "Fix API access issues",
            "details": {
                "error": str(e)
            }
        })
    
    return findings

def awslambda_function_layer_region_compliance(region_name: str, profile_name: str = None) -> Dict[str, Any]:
    """
    Main function wrapper for awslambda_function_layer_region_compliance.
    
    Args:
        region_name (str): AWS region name
        profile_name (str): AWS profile name (optional)
        
    Returns:
        Dict: Results summary
    """
    COMPLIANCE_DATA = load_rule_metadata("awslambda_function_layer_region_compliance")
    
    # TODO: Implement SecurityEngine integration when available
    # from data_security_engine import SecurityEngine
    # engine = SecurityEngine(COMPLIANCE_DATA)
    # return engine.run_check(region_name, profile_name, awslambda_function_layer_region_compliance_check)
    
    # Current implementation
    findings = awslambda_function_layer_region_compliance_check(region_name, profile_name)
    
    # Calculate compliance statistics
    total_findings = len(findings)
    compliant_findings = len([f for f in findings if f['status'] == 'COMPLIANT'])
    non_compliant_findings = len([f for f in findings if f['status'] == 'NON_COMPLIANT'])
    error_findings = len([f for f in findings if f['status'] == 'ERROR'])
    
    return {
        "function_name": "awslambda_function_layer_region_compliance",
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
    """CLI entry point for awslambda_function_layer_region_compliance."""
    # TODO: Implement setup_command_line_interface() when data_security_engine is available
    # from data_security_engine import setup_command_line_interface, save_results, exit_with_status
    # args = setup_command_line_interface()
    # results = awslambda_function_layer_region_compliance(args.region, args.profile)
    # save_results(results, args.output_file)
    # exit_with_status(results)
    
    # Current CLI implementation
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Ensure Lambda layers are shared only within approved regions to maintain data residency compliance."
    )
    parser.add_argument("--region", default="us-east-1", help="AWS region")
    parser.add_argument("--profile", help="AWS profile name")
    parser.add_argument("--output", help="Output file for results (JSON format)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        results = awslambda_function_layer_region_compliance(args.region, args.profile)
        
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

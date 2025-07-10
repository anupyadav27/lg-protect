#!/usr/bin/env python3
"""
pci_4.0_aws - ecs_task_definitions_host_namespace_not_shared

Checks if ECS Task Definitions are configured to share a host's process namespace with its Amazon Elastic Container Service (Amazon ECS) containers
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
        'compliance_name': 'pci_4.0_aws',
        'function_name': 'ecs_task_definitions_host_namespace_not_shared',
        'id': 'ECS.2',
        'name': 'ECS task definitions should not share the host process namespace',
        'description': 'Checks if ECS Task Definitions are configured to share a host\'s process namespace with its Amazon Elastic Container Service (Amazon ECS) containers',
        'api_function': 'client = boto3.client(\'ecs\')',
        'user_function': 'list_task_definitions(), describe_task_definition()',
        'risk_level': 'HIGH',
        'recommendation': 'Ensure ECS task definitions do not have pidMode set to host to prevent sharing the host process namespace'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('ecs_task_definitions_host_namespace_not_shared')

def ecs_task_definitions_host_namespace_not_shared_check(ecs_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for ecs_task_definitions_host_namespace_not_shared.
    
    Args:
        ecs_client: Boto3 ECS client (auto-created by framework)
        region (str): AWS region (auto-managed by framework)
        profile (str): AWS profile name (auto-managed by framework)
        logger: Logger instance (auto-configured by framework)
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    try:
        logger.info(f"Checking ECS task definitions for host namespace sharing in region {region}")
        
        # Get all task definition ARNs
        task_definitions_response = ecs_client.list_task_definitions(
            status='ACTIVE'
        )
        
        task_definition_arns = task_definitions_response.get('taskDefinitionArns', [])
        
        if not task_definition_arns:
            logger.info(f"No active task definitions found in region {region}")
            return findings
        
        # Check each task definition
        for task_def_arn in task_definition_arns:
            try:
                # Get detailed task definition information
                task_def_response = ecs_client.describe_task_definition(
                    taskDefinition=task_def_arn
                )
                
                task_definition = task_def_response.get('taskDefinition', {})
                family = task_definition.get('family', 'unknown')
                revision = task_definition.get('revision', 'unknown')
                task_def_id = f"{family}:{revision}"
                
                # Check if pidMode is set to 'host'
                pid_mode = task_definition.get('pidMode', None)
                
                if pid_mode == 'host':
                    # Non-compliant: Task definition shares host process namespace
                    finding = {
                        'region': region,
                        'profile': profile,
                        'resource_type': 'ECS Task Definition',
                        'resource_id': task_def_id,
                        'status': 'NON_COMPLIANT',
                        'compliance_status': 'FAIL',
                        'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                        'recommendation': COMPLIANCE_DATA.get('recommendation', 'Ensure ECS task definitions do not have pidMode set to host'),
                        'details': {
                            'task_definition_arn': task_def_arn,
                            'family': family,
                            'revision': revision,
                            'pid_mode': pid_mode,
                            'issue': 'Task definition is configured to share the host process namespace (pidMode: host)',
                            'network_mode': task_definition.get('networkMode', 'unknown'),
                            'cpu': task_definition.get('cpu', 'unknown'),
                            'memory': task_definition.get('memory', 'unknown')
                        }
                    }
                else:
                    # Compliant: Task definition does not share host process namespace
                    finding = {
                        'region': region,
                        'profile': profile,
                        'resource_type': 'ECS Task Definition',
                        'resource_id': task_def_id,
                        'status': 'COMPLIANT',
                        'compliance_status': 'PASS',
                        'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                        'recommendation': COMPLIANCE_DATA.get('recommendation', 'Task definition properly configured'),
                        'details': {
                            'task_definition_arn': task_def_arn,
                            'family': family,
                            'revision': revision,
                            'pid_mode': pid_mode if pid_mode else 'default (task)',
                            'network_mode': task_definition.get('networkMode', 'unknown'),
                            'cpu': task_definition.get('cpu', 'unknown'),
                            'memory': task_definition.get('memory', 'unknown')
                        }
                    }
                
                findings.append(finding)
                
            except Exception as e:
                logger.error(f"Error checking task definition {task_def_arn} in {region}: {e}")
                findings.append({
                    'region': region,
                    'profile': profile,
                    'resource_type': 'ECS Task Definition',
                    'resource_id': task_def_arn.split('/')[-1] if '/' in task_def_arn else task_def_arn,
                    'status': 'ERROR',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Review and remediate as needed'),
                    'error': str(e)
                })
        
    except Exception as e:
        logger.error(f"Error in ecs_task_definitions_host_namespace_not_shared check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'ECS Task Definition',
            'status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Review and remediate as needed'),
            'error': str(e)
        })
        
    return findings

def ecs_task_definitions_host_namespace_not_shared(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=ecs_task_definitions_host_namespace_not_shared_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = ecs_task_definitions_host_namespace_not_shared(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

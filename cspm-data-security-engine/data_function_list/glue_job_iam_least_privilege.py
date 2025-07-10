#!/usr/bin/env python3
"""
data_security_aws - glue_job_iam_least_privilege

Ensure Glue jobs use IAM roles with least privilege to minimize unauthorized access to data during processing.
"""

# Rule Metadata from YAML:
# Function Name: glue_job_iam_least_privilege
# Capability: ACCESS_GOVERNANCE
# Service: GLUE
# Subservice: IAM
# Description: Ensure Glue jobs use IAM roles with least privilege to minimize unauthorized access to data during processing.
# Risk Level: MEDIUM
# Recommendation: Enforce least privilege for Glue job IAM roles
# API Function: client = boto3.client('glue')
# User Function: glue_job_iam_least_privilege()

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
        "function_name": "glue_job_iam_least_privilege",
        "title": "Enforce least privilege for Glue job IAM roles",
        "description": "Ensure Glue jobs use IAM roles with least privilege to minimize unauthorized access to data during processing.",
        "capability": "access_governance",
        "service": "glue",
        "subservice": "iam",
        "risk": "MEDIUM",
        "existing": False
    }

def glue_job_iam_least_privilege_check(region_name: str, profile_name: str = None) -> List[Dict[str, Any]]:
    """
    Check glue resources for access_governance compliance.
    
    Args:
        region_name (str): AWS region name
        profile_name (str): AWS profile name (optional)
        
    Returns:
        List[Dict]: List of compliance findings
    """
    findings = []
    
    try:
        # Initialize boto3 clients
        session = boto3.Session(profile_name=profile_name)
        glue_client = session.client('glue', region_name=region_name)
        iam_client = session.client('iam')
        
        logger.info(f"Checking Glue resources for access_governance compliance in region {region_name}")
        
        # Get all Glue jobs
        paginator = glue_client.get_paginator('get_jobs')
        
        for page in paginator.paginate():
            jobs = page.get('Jobs', [])
            
            for job in jobs:
                job_name = job.get('Name')
                job_arn = f"arn:aws:glue:{region_name}:{session.client('sts').get_caller_identity()['Account']}:job/{job_name}"
                role_arn = job.get('Role')
                
                if not role_arn:
                    findings.append({
                        "region": region_name,
                        "profile": profile_name or "default",
                        "resource_type": "glue_job",
                        "resource_id": job_arn,
                        "status": "NON_COMPLIANT",
                        "risk_level": "MEDIUM",
                        "recommendation": "Glue job must have an IAM role assigned",
                        "details": {
                            "job_name": job_name,
                            "job_arn": job_arn,
                            "violation": "No IAM role assigned to Glue job",
                            "glue_version": job.get('GlueVersion'),
                            "worker_type": job.get('WorkerType')
                        }
                    })
                    continue
                
                try:
                    # Extract role name from ARN
                    role_name = role_arn.split('/')[-1]
                    
                    # Get role details
                    role_response = iam_client.get_role(RoleName=role_name)
                    role = role_response.get('Role', {})
                    
                    # Check attached and inline policies
                    attached_policies = iam_client.list_attached_role_policies(RoleName=role_name)
                    inline_policies = iam_client.list_role_policies(RoleName=role_name)
                    
                    privilege_violations = []
                    policy_analysis = {
                        'attached_policies': [],
                        'inline_policies': [],
                        'overly_permissive_actions': [],
                        'wildcard_resources': [],
                        'admin_policies': []
                    }
                    
                    # Analyze attached managed policies
                    for policy in attached_policies.get('AttachedPolicies', []):
                        policy_arn = policy.get('PolicyArn')
                        policy_name = policy.get('PolicyName')
                        
                        policy_analysis['attached_policies'].append({
                            'name': policy_name,
                            'arn': policy_arn
                        })
                        
                        # Check for overly permissive policies
                        if any(admin_policy in policy_name.lower() for admin_policy in 
                               ['administratoraccess', 'poweruseraccess', 'fullaccess']):
                            privilege_violations.append(f"Overly permissive managed policy: {policy_name}")
                            policy_analysis['admin_policies'].append(policy_name)
                        
                        # Get policy document for detailed analysis
                        try:
                            policy_response = iam_client.get_policy(PolicyArn=policy_arn)
                            policy_version = iam_client.get_policy_version(
                                PolicyArn=policy_arn,
                                VersionId=policy_response['Policy']['DefaultVersionId']
                            )
                            
                            policy_document = policy_version.get('PolicyVersion', {}).get('Document', {})
                            statements = policy_document.get('Statement', [])
                            
                            for statement in statements:
                                if isinstance(statement, dict):
                                    # Check for overly broad actions
                                    actions = statement.get('Action', [])
                                    if isinstance(actions, str):
                                        actions = [actions]
                                    
                                    for action in actions:
                                        if '*' in action and action != 'glue:*':
                                            policy_analysis['overly_permissive_actions'].append({
                                                'policy': policy_name,
                                                'action': action
                                            })
                                    
                                    # Check for wildcard resources
                                    resources = statement.get('Resource', [])
                                    if isinstance(resources, str):
                                        resources = [resources]
                                    
                                    for resource in resources:
                                        if resource == '*':
                                            policy_analysis['wildcard_resources'].append({
                                                'policy': policy_name,
                                                'resource': resource
                                            })
                        
                        except Exception as policy_error:
                            logger.warning(f"Failed to analyze policy {policy_name}: {policy_error}")
                    
                    # Analyze inline policies
                    for policy_name in inline_policies.get('PolicyNames', []):
                        policy_analysis['inline_policies'].append(policy_name)
                        
                        try:
                            policy_response = iam_client.get_role_policy(
                                RoleName=role_name,
                                PolicyName=policy_name
                            )
                            policy_document = policy_response.get('PolicyDocument', {})
                            statements = policy_document.get('Statement', [])
                            
                            for statement in statements:
                                if isinstance(statement, dict):
                                    # Check for overly broad actions
                                    actions = statement.get('Action', [])
                                    if isinstance(actions, str):
                                        actions = [actions]
                                    
                                    for action in actions:
                                        if '*' in action and not action.startswith('glue:'):
                                            policy_analysis['overly_permissive_actions'].append({
                                                'policy': policy_name,
                                                'action': action
                                            })
                                    
                                    # Check for wildcard resources
                                    resources = statement.get('Resource', [])
                                    if isinstance(resources, str):
                                        resources = [resources]
                                    
                                    for resource in resources:
                                        if resource == '*':
                                            policy_analysis['wildcard_resources'].append({
                                                'policy': policy_name,
                                                'resource': resource
                                            })
                        
                        except Exception as inline_error:
                            logger.warning(f"Failed to analyze inline policy {policy_name}: {inline_error}")
                    
                    # Check for common least privilege violations
                    if policy_analysis['overly_permissive_actions']:
                        privilege_violations.append(f"Found {len(policy_analysis['overly_permissive_actions'])} wildcard actions")
                    
                    if policy_analysis['wildcard_resources']:
                        privilege_violations.append(f"Found {len(policy_analysis['wildcard_resources'])} wildcard resources")
                    
                    if len(policy_analysis['attached_policies']) > 8:
                        privilege_violations.append(f"Too many attached policies: {len(policy_analysis['attached_policies'])}")
                    
                    if len(policy_analysis['inline_policies']) > 3:
                        privilege_violations.append(f"Too many inline policies: {len(policy_analysis['inline_policies'])}")
                    
                    # Determine compliance status
                    if privilege_violations:
                        findings.append({
                            "region": region_name,
                            "profile": profile_name or "default",
                            "resource_type": "glue_job",
                            "resource_id": job_arn,
                            "status": "NON_COMPLIANT",
                            "risk_level": "MEDIUM",
                            "recommendation": "Apply least privilege principles to Glue job IAM role",
                            "details": {
                                "job_name": job_name,
                                "job_arn": job_arn,
                                "role_arn": role_arn,
                                "role_name": role_name,
                                "violation": "; ".join(privilege_violations),
                                "privilege_violations": privilege_violations,
                                "policy_analysis": policy_analysis,
                                "glue_version": job.get('GlueVersion'),
                                "worker_type": job.get('WorkerType')
                            }
                        })
                    else:
                        findings.append({
                            "region": region_name,
                            "profile": profile_name or "default",
                            "resource_type": "glue_job",
                            "resource_id": job_arn,
                            "status": "COMPLIANT",
                            "risk_level": "MEDIUM",
                            "recommendation": "Glue job IAM role follows least privilege principles",
                            "details": {
                                "job_name": job_name,
                                "job_arn": job_arn,
                                "role_arn": role_arn,
                                "role_name": role_name,
                                "policy_summary": {
                                    "attached_policies_count": len(policy_analysis['attached_policies']),
                                    "inline_policies_count": len(policy_analysis['inline_policies']),
                                    "has_wildcard_actions": len(policy_analysis['overly_permissive_actions']) > 0,
                                    "has_wildcard_resources": len(policy_analysis['wildcard_resources']) > 0
                                },
                                "glue_version": job.get('GlueVersion'),
                                "worker_type": job.get('WorkerType')
                            }
                        })
                
                except iam_client.exceptions.NoSuchEntityException:
                    findings.append({
                        "region": region_name,
                        "profile": profile_name or "default",
                        "resource_type": "glue_job",
                        "resource_id": job_arn,
                        "status": "NON_COMPLIANT",
                        "risk_level": "MEDIUM",
                        "recommendation": "Glue job references non-existent IAM role",
                        "details": {
                            "job_name": job_name,
                            "job_arn": job_arn,
                            "role_arn": role_arn,
                            "violation": "Referenced IAM role does not exist",
                            "glue_version": job.get('GlueVersion'),
                            "worker_type": job.get('WorkerType')
                        }
                    })
                
                except Exception as job_error:
                    logger.warning(f"Failed to check job {job_name}: {job_error}")
                    findings.append({
                        "region": region_name,
                        "profile": profile_name or "default",
                        "resource_type": "glue_job",
                        "resource_id": job_arn,
                        "status": "ERROR",
                        "risk_level": "MEDIUM",
                        "recommendation": "Unable to check IAM least privilege configuration",
                        "details": {
                            "job_name": job_name,
                            "job_arn": job_arn,
                            "error": str(job_error)
                        }
                    })
        
        logger.info(f"Completed checking glue_job_iam_least_privilege. Found {len(findings)} findings.")
        
    except Exception as e:
        logger.error(f"Failed to check glue_job_iam_least_privilege: {e}")
        findings.append({
            "region": region_name,
            "profile": profile_name or "default",
            "resource_type": "glue_job",
            "resource_id": "unknown",
            "status": "ERROR",
            "risk_level": "MEDIUM",
            "recommendation": "Fix API access issues",
            "details": {
                "error": str(e)
            }
        })
    
    return findings

def glue_job_iam_least_privilege(region_name: str, profile_name: str = None) -> Dict[str, Any]:
    """
    Main function wrapper for glue_job_iam_least_privilege.
    
    Args:
        region_name (str): AWS region name
        profile_name (str): AWS profile name (optional)
        
    Returns:
        Dict: Results summary
    """
    COMPLIANCE_DATA = load_rule_metadata("glue_job_iam_least_privilege")
    
    # TODO: Implement SecurityEngine integration when available
    # from data_security_engine import SecurityEngine
    # engine = SecurityEngine(COMPLIANCE_DATA)
    # return engine.run_check(region_name, profile_name, glue_job_iam_least_privilege_check)
    
    # Current implementation
    findings = glue_job_iam_least_privilege_check(region_name, profile_name)
    
    # Calculate compliance statistics
    total_findings = len(findings)
    compliant_findings = len([f for f in findings if f['status'] == 'COMPLIANT'])
    non_compliant_findings = len([f for f in findings if f['status'] == 'NON_COMPLIANT'])
    error_findings = len([f for f in findings if f['status'] == 'ERROR'])
    
    return {
        "function_name": "glue_job_iam_least_privilege",
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
    """CLI entry point for glue_job_iam_least_privilege."""
    # TODO: Implement setup_command_line_interface() when data_security_engine is available
    # from data_security_engine import setup_command_line_interface, save_results, exit_with_status
    # args = setup_command_line_interface()
    # results = glue_job_iam_least_privilege(args.region, args.profile)
    # save_results(results, args.output_file)
    # exit_with_status(results)
    
    # Current CLI implementation
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Ensure Glue jobs use IAM roles with least privilege to minimize unauthorized access to data during processing."
    )
    parser.add_argument("--region", default="us-east-1", help="AWS region")
    parser.add_argument("--profile", help="AWS profile name")
    parser.add_argument("--output", help="Output file for results (JSON format)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        results = glue_job_iam_least_privilege(args.region, args.profile)
        
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

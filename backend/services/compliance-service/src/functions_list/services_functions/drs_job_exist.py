#!/usr/bin/env python3
"""
aws_foundational_security_best_practices_aws - drs_job_exist

Ensure AWS Elastic Disaster Recovery (DRS) jobs exist to provide business continuity and disaster recovery capabilities.
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
                    'recommendation': entry.get('Recommendation', 'Set up AWS DRS jobs for disaster recovery')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'aws_foundational_security_best_practices_aws',
        'function_name': 'drs_job_exist',
        'id': 'AWS-FSBP-DRS.1',
        'name': 'DRS Jobs Existence',
        'description': 'Ensure AWS Elastic Disaster Recovery (DRS) jobs exist to provide business continuity and disaster recovery capabilities.',
        'api_function': 'client=boto3.client(\'drs\')',
        'user_function': 'describe_jobs()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Set up AWS DRS jobs for critical workloads to ensure business continuity'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('drs_job_exist')

def drs_job_exist_check(drs_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for drs_job_exist.
    
    Args:
        drs_client: Boto3 DRS client (auto-created by framework)
        region (str): AWS region (auto-managed by framework)
        profile (str): AWS profile name (auto-managed by framework)
        logger: Logger instance (auto-configured by framework)
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    try:
        # Check if DRS service is initialized first
        try:
            init_response = drs_client.describe_replication_configuration_templates()
            logger.info("DRS service is initialized in this region")
        except drs_client.exceptions.UninitializedAccountException:
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'DRS',
                'resource_id': f'drs-uninitialized-{region}',
                'status': 'NON_COMPLIANT',
                'compliance_status': 'FAIL',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                'recommendation': 'Initialize AWS DRS service and set up disaster recovery jobs',
                'details': {
                    'service_status': 'uninitialized',
                    'message': 'AWS DRS service is not initialized in this region'
                }
            }
            findings.append(finding)
            return findings
        except Exception as init_error:
            logger.warning(f"Unable to check DRS initialization status: {init_error}")
        
        # Get all DRS jobs
        response = drs_client.describe_jobs()
        jobs = response.get('items', [])
        
        # Also check for source servers (which indicate DR setup)
        try:
            source_servers_response = drs_client.describe_source_servers()
            source_servers = source_servers_response.get('items', [])
        except Exception as source_error:
            logger.warning(f"Unable to describe source servers: {source_error}")
            source_servers = []
        
        if not jobs and not source_servers:
            # No DRS jobs or source servers found - this is non-compliant
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'DRS',
                'resource_id': f'no-dr-setup-{region}',
                'status': 'NON_COMPLIANT',
                'compliance_status': 'FAIL',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                'recommendation': COMPLIANCE_DATA.get('recommendation', 'Set up AWS DRS jobs for disaster recovery'),
                'details': {
                    'jobs_count': 0,
                    'source_servers_count': 0,
                    'message': 'No DRS jobs or source servers found - disaster recovery not configured'
                }
            }
            findings.append(finding)
            return findings
        
        # Check jobs if they exist
        for job in jobs:
            job_id = job.get('jobID', 'unknown')
            job_type = job.get('type', 'unknown')
            
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'DRS',
                'resource_id': job_id,
                'status': 'COMPLIANT',
                'compliance_status': 'PASS',
                'risk_level': 'LOW',
                'recommendation': 'DRS job exists - monitor job status and success',
                'details': {
                    'job_id': job_id,
                    'job_type': job_type,
                    'status': job.get('status', 'unknown'),
                    'creation_date_time': job.get('creationDateTime', 'unknown'),
                    'end_date_time': job.get('endDateTime', 'unknown'),
                    'initiated_by': job.get('initiatedBy', 'unknown'),
                    'arn': job.get('arn', 'unknown'),
                    'tags': job.get('tags', {})
                }
            }
            findings.append(finding)
        
        # If we have source servers but no recent jobs, create a finding
        if source_servers and not jobs:
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'DRS',
                'resource_id': f'source-servers-{region}',
                'status': 'COMPLIANT',
                'compliance_status': 'PASS',
                'risk_level': 'LOW',
                'recommendation': 'DRS source servers configured - consider running test jobs periodically',
                'details': {
                    'source_servers_count': len(source_servers),
                    'jobs_count': 0,
                    'message': 'DRS source servers are configured for disaster recovery'
                }
            }
            findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in drs_job_exist check for {region}: {e}")
        
        # Check if this is a service not available error
        if 'is not available' in str(e) or 'not supported' in str(e):
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'DRS',
                'resource_id': f'service-unavailable-{region}',
                'status': 'COMPLIANT',
                'compliance_status': 'PASS',
                'risk_level': 'LOW',
                'recommendation': 'DRS service is not available in this region',
                'details': {
                    'service_status': 'unavailable',
                    'message': f'AWS DRS service is not available in region {region}'
                }
            }
        else:
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'DRS',
                'resource_id': f'error-check-{region}',
                'status': 'ERROR',
                'compliance_status': 'ERROR',
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                'recommendation': COMPLIANCE_DATA.get('recommendation', 'Set up AWS DRS jobs for disaster recovery'),
                'error': str(e)
            }
        
        findings.append(finding)
        
    return findings

def drs_job_exist(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=drs_job_exist_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = drs_job_exist(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

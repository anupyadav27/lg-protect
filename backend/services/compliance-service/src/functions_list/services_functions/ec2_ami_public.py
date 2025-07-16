#!/usr/bin/env python3
"""
iso27001_2013_aws - ec2_ami_public

Check for publicly shared AMIs
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
                    'recommendation': entry.get('Recommendation', 'Remove public access from AMIs')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'iso27001_2013_aws',
        'function_name': 'ec2_ami_public',
        'id': 'A.12.6',
        'name': 'Technical Vulnerability Management',
        'description': 'Check for publicly shared AMIs',
        'api_function': 'client=boto3.client(\'ec2\')',
        'user_function': 'describe_images()',
        'risk_level': 'HIGH',
        'recommendation': 'Remove public access from AMIs to prevent unauthorized access'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('ec2_ami_public')

def ec2_ami_public_check(ec2_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for ec2_ami_public.
    
    Args:
        ec2_client: Boto3 EC2 client (auto-created by framework)
        region (str): AWS region (auto-managed by framework)
        profile (str): AWS profile name (auto-managed by framework)
        logger: Logger instance (auto-configured by framework)
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    try:
        # Get AMIs owned by this account
        response = ec2_client.describe_images(Owners=['self'])
        images = response.get('Images', [])
        
        if not images:
            # No AMIs found, create an informational finding
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'AMI',
                'resource_id': f'no-amis-{region}',
                'status': 'COMPLIANT',
                'compliance_status': 'PASS',
                'risk_level': 'LOW',
                'recommendation': 'No AMIs found in this region',
                'details': {
                    'amis_count': 0,
                    'message': 'No AMIs found to check for public access'
                }
            }
            findings.append(finding)
            return findings
        
        for image in images:
            image_id = image.get('ImageId', 'unknown')
            name = image.get('Name', 'unknown')
            state = image.get('State', 'unknown')
            public = image.get('Public', False)
            architecture = image.get('Architecture', 'unknown')
            creation_date = image.get('CreationDate', 'unknown')
            
            # Determine compliance status
            if public:
                status = 'NON_COMPLIANT'
                compliance_status = 'FAIL'
                risk_level = COMPLIANCE_DATA.get('risk_level', 'HIGH')
                recommendation = COMPLIANCE_DATA.get('recommendation', 'Remove public access from this AMI')
            else:
                status = 'COMPLIANT'
                compliance_status = 'PASS'
                risk_level = 'LOW'
                recommendation = 'AMI is not publicly accessible'
            
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'AMI',
                'resource_id': image_id,
                'status': status,
                'compliance_status': compliance_status,
                'risk_level': risk_level,
                'recommendation': recommendation,
                'details': {
                    'image_id': image_id,
                    'name': name,
                    'public': public,
                    'state': state,
                    'architecture': architecture,
                    'creation_date': creation_date,
                    'is_compliant': not public,
                    'security_note': 'Public AMIs can be accessed and launched by anyone'
                }
            }
            
            findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in ec2_ami_public check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'AMI',
            'resource_id': f'error-check-{region}',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Remove public access from AMIs'),
            'error': str(e)
        })
        
    return findings

def ec2_ami_public(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=ec2_ami_public_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = ec2_ami_public(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

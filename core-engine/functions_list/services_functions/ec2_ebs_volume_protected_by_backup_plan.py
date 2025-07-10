#!/usr/bin/env python3
"""
iso27001_2022_aws - ec2_ebs_volume_protected_by_backup_plan

Information processing facilities should be implemented with redundancy sufficient to meet availability
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
                    'risk_level': entry.get('Risk Level', 'HIGH'),
                    'recommendation': entry.get('Recommendation', 'Ensure EBS volumes are protected by AWS Backup plans for data redundancy')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'iso27001_2022_aws',
        'function_name': 'ec2_ebs_volume_protected_by_backup_plan',
        'id': 'ISO-27001-2022-A.11.1',
        'name': 'Backup and Recovery',
        'description': 'Information processing facilities should be implemented with redundancy sufficient to meet availability',
        'api_function': 'client=boto3.client(\'backup\')',
        'user_function': 'list_backup_vaults()',
        'risk_level': 'HIGH',
        'recommendation': 'Ensure EBS volumes are protected by AWS Backup plans for data redundancy'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('ec2_ebs_volume_protected_by_backup_plan')

def get_backup_protected_resources(backup_client, logger) -> Dict[str, List[str]]:
    """
    Get list of resources protected by backup plans.
    
    Args:
        backup_client: Boto3 Backup client
        logger: Logger instance
        
    Returns:
        dict: Dictionary mapping resource types to lists of protected resource ARNs
    """
    protected_resources = {
        'ebs_volumes': []
    }
    
    try:
        # Get all backup plans
        backup_plans_response = backup_client.list_backup_plans()
        backup_plans = backup_plans_response.get('BackupPlansList', [])
        
        for plan in backup_plans:
            plan_id = plan.get('BackupPlanId')
            
            try:
                # Get backup selections for this plan
                selections_response = backup_client.list_backup_selections(BackupPlanId=plan_id)
                selections = selections_response.get('BackupSelectionsList', [])
                
                for selection in selections:
                    selection_id = selection.get('SelectionId')
                    
                    try:
                        # Get detailed backup selection
                        selection_detail = backup_client.get_backup_selection(
                            BackupPlanId=plan_id,
                            SelectionId=selection_id
                        )
                        
                        backup_selection = selection_detail.get('BackupSelection', {})
                        resources = backup_selection.get('Resources', [])
                        
                        # Filter for EBS volume ARNs
                        for resource_arn in resources:
                            if ':volume/' in resource_arn:
                                protected_resources['ebs_volumes'].append(resource_arn)
                        
                        # Check for resource assignments by tags or conditions
                        conditions = backup_selection.get('Conditions', {})
                        if conditions:
                            # This is a tag-based or condition-based selection
                            # We'd need to query actual resources to see what's covered
                            logger.info(f"Found condition-based backup selection: {selection.get('SelectionName')}")
                            
                    except Exception as e:
                        logger.warning(f"Error getting backup selection details for {selection_id}: {e}")
                        
            except Exception as e:
                logger.warning(f"Error listing backup selections for plan {plan_id}: {e}")
                
    except Exception as e:
        logger.error(f"Error listing backup plans: {e}")
    
    return protected_resources

def ec2_ebs_volume_protected_by_backup_plan_check(backup_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for ec2_ebs_volume_protected_by_backup_plan.
    
    Args:
        backup_client: Boto3 Backup client (auto-created by framework)
        region (str): AWS region (auto-managed by framework)
        profile (str): AWS profile name (auto-managed by framework)
        logger: Logger instance (auto-configured by framework)
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    try:
        # First check if backup service is available in region
        try:
            backup_vaults_response = backup_client.list_backup_vaults()
            backup_vaults = backup_vaults_response.get('BackupVaultList', [])
        except Exception as backup_error:
            # Backup service might not be available in this region
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'BackupService',
                'resource_id': f'backup-service-{region}',
                'status': 'ERROR',
                'compliance_status': 'ERROR',
                'risk_level': 'MEDIUM',
                'recommendation': 'AWS Backup service may not be available in this region',
                'details': {
                    'service_availability': False,
                    'error': str(backup_error),
                    'message': 'Cannot check EBS volume backup protection without Backup service'
                }
            }
            findings.append(finding)
            return findings
        
        # Get protected resources from backup plans
        protected_resources = get_backup_protected_resources(backup_client, logger)
        protected_ebs_volumes = protected_resources['ebs_volumes']
        
        # Get list of all EBS volumes to check
        # We need EC2 client for this
        import boto3
        try:
            session = backup_client._client_config.__dict__.get('_user_provided_options', {})
            region_name = session.get('region_name', region)
            
            # Create EC2 client with same session as backup client
            ec2_client = boto3.client('ec2', region_name=region_name)
            
            volumes_response = ec2_client.describe_volumes()
            volumes = volumes_response.get('Volumes', [])
            
        except Exception as ec2_error:
            logger.error(f"Error accessing EC2 service to list volumes: {ec2_error}")
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'EC2Service',
                'resource_id': f'ec2-service-{region}',
                'status': 'ERROR',
                'compliance_status': 'ERROR',
                'risk_level': 'MEDIUM',
                'recommendation': 'Cannot access EC2 service to list EBS volumes',
                'details': {
                    'service_error': str(ec2_error),
                    'backup_vaults_count': len(backup_vaults),
                    'protected_volumes_count': len(protected_ebs_volumes)
                }
            }
            findings.append(finding)
            return findings
        
        if not volumes:
            # No EBS volumes found
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'EBSVolume',
                'resource_id': f'no-ebs-volumes-{region}',
                'status': 'COMPLIANT',
                'compliance_status': 'PASS',
                'risk_level': 'LOW',
                'recommendation': 'No EBS volumes found in this region',
                'details': {
                    'volumes_count': 0,
                    'backup_vaults_count': len(backup_vaults),
                    'protected_volumes_count': len(protected_ebs_volumes),
                    'message': 'No EBS volumes found to check for backup protection'
                }
            }
            findings.append(finding)
            return findings
        
        # Check each volume for backup protection
        unprotected_count = 0
        for volume in volumes:
            volume_id = volume.get('VolumeId', 'unknown')
            volume_state = volume.get('State', 'unknown')
            volume_size = volume.get('Size', 0)
            volume_type = volume.get('VolumeType', 'unknown')
            
            # Create volume ARN for comparison
            volume_arn = f"arn:aws:ec2:{region}:{volume.get('OwnerId', '*')}:volume/{volume_id}"
            
            # Check if volume is protected by backup
            is_protected = volume_arn in protected_ebs_volumes
            
            # Additional check for tag-based backup selections would require
            # checking volume tags against backup selection conditions
            # This is a simplified implementation
            
            if is_protected:
                status = 'COMPLIANT'
                compliance_status = 'PASS'
                risk_level = 'LOW'
                recommendation = 'EBS volume is protected by AWS Backup plan'
            else:
                unprotected_count += 1
                status = 'NON_COMPLIANT'
                compliance_status = 'FAIL'
                risk_level = COMPLIANCE_DATA.get('risk_level', 'HIGH')
                recommendation = COMPLIANCE_DATA.get('recommendation', 'Add EBS volume to AWS Backup plan')
            
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'EBSVolume',
                'resource_id': volume_id,
                'status': status,
                'compliance_status': compliance_status,
                'risk_level': risk_level,
                'recommendation': recommendation,
                'details': {
                    'volume_id': volume_id,
                    'volume_arn': volume_arn,
                    'volume_state': volume_state,
                    'volume_size_gb': volume_size,
                    'volume_type': volume_type,
                    'is_protected_by_backup': is_protected,
                    'availability_zone': volume.get('AvailabilityZone', 'unknown'),
                    'creation_time': volume.get('CreateTime', '').isoformat() if volume.get('CreateTime') else None,
                    'encrypted': volume.get('Encrypted', False),
                    'attachments': volume.get('Attachments', []),
                    'tags': volume.get('Tags', []),
                    'security_note': 'Regular backups are essential for data protection and disaster recovery'
                }
            }
            
            findings.append(finding)
        
        logger.info(f"Checked {len(volumes)} EBS volumes, found {unprotected_count} not protected by backup plans")
        
    except Exception as e:
        logger.error(f"Error in ec2_ebs_volume_protected_by_backup_plan check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'EBSVolume',
            'resource_id': f'error-check-{region}',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Ensure EBS volumes are protected by backup plans'),
            'error': str(e)
        })
        
    return findings

def ec2_ebs_volume_protected_by_backup_plan(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=ec2_ebs_volume_protected_by_backup_plan_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = ec2_ebs_volume_protected_by_backup_plan(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

#!/usr/bin/env python3
"""
iso27001_2022_aws - storagegateway_fileshare_encryption_enabled

Rules for the effective use of cryptography, including cryptographic key management, should be defined and implemented.
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
        'compliance_name': 'iso27001_2022_aws',
        'function_name': 'storagegateway_fileshare_encryption_enabled',
        'id': 'SGW-001',
        'name': 'Storage Gateway File Share Encryption',
        'description': 'Rules for the effective use of cryptography, including cryptographic key management, should be defined and implemented.',
        'api_function': 'client=boto3.client("storagegateway")',
        'user_function': 'list_gateways(), describe_nfs_file_shares(), describe_smb_file_shares()',
        'risk_level': 'HIGH',
        'recommendation': 'Enable encryption for all Storage Gateway file shares to protect data at rest and in transit'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('storagegateway_fileshare_encryption_enabled')

def storagegateway_fileshare_encryption_enabled_check(storagegateway_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for storagegateway_fileshare_encryption_enabled.
    
    Args:
        storagegateway_client: Boto3 Storage Gateway client (auto-created by framework)
        region (str): AWS region (auto-managed by framework)
        profile (str): AWS profile name (auto-managed by framework)
        logger: Logger instance (auto-configured by framework)
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    try:
        # List all gateways
        gateways_response = storagegateway_client.list_gateways()
        gateways = gateways_response.get('Gateways', [])
        
        if not gateways:
            logger.info(f"No Storage Gateways found in region {region}")
            return findings
        
        for gateway in gateways:
            gateway_arn = gateway.get('GatewayARN', 'Unknown')
            gateway_id = gateway.get('GatewayId', 'Unknown')
            gateway_name = gateway.get('GatewayName', 'Unknown')
            gateway_type = gateway.get('GatewayType', 'Unknown')
            
            # Only check file gateways
            if gateway_type not in ['FILE_S3', 'FILE_FSX_SMB']:
                logger.debug(f"Skipping gateway {gateway_id} - not a file gateway (type: {gateway_type})")
                continue
            
            try:
                # Check NFS file shares
                try:
                    nfs_response = storagegateway_client.describe_nfs_file_shares(
                        GatewayARN=gateway_arn
                    )
                    nfs_shares = nfs_response.get('NFSFileShareInfoList', [])
                    
                    for share in nfs_shares:
                        share_arn = share.get('FileShareARN', 'Unknown')
                        share_id = share.get('FileShareId', 'Unknown')
                        kms_encrypted = share.get('KMSEncrypted', False)
                        kms_key = share.get('KMSKey', '')
                        
                        if kms_encrypted:
                            # NFS share is encrypted - COMPLIANT
                            finding = {
                                'region': region,
                                'profile': profile,
                                'resource_type': 'StorageGateway_NFS_FileShare',
                                'resource_id': f"{share_id} ({gateway_name})",
                                'status': 'COMPLIANT',
                                'compliance_status': 'PASS',
                                'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                                'recommendation': COMPLIANCE_DATA.get('recommendation', 'Maintain encryption settings'),
                                'details': {
                                    'file_share_arn': share_arn,
                                    'file_share_id': share_id,
                                    'gateway_name': gateway_name,
                                    'gateway_id': gateway_id,
                                    'share_type': 'NFS',
                                    'kms_encrypted': True,
                                    'kms_key': kms_key,
                                    'location_arn': share.get('LocationARN', 'Unknown'),
                                    'path': share.get('Path', 'Unknown')
                                }
                            }
                        else:
                            # NFS share is not encrypted - NON_COMPLIANT
                            finding = {
                                'region': region,
                                'profile': profile,
                                'resource_type': 'StorageGateway_NFS_FileShare',
                                'resource_id': f"{share_id} ({gateway_name})",
                                'status': 'NON_COMPLIANT',
                                'compliance_status': 'FAIL',
                                'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                                'recommendation': 'Enable KMS encryption for this NFS file share',
                                'details': {
                                    'file_share_arn': share_arn,
                                    'file_share_id': share_id,
                                    'gateway_name': gateway_name,
                                    'gateway_id': gateway_id,
                                    'share_type': 'NFS',
                                    'kms_encrypted': False,
                                    'location_arn': share.get('LocationARN', 'Unknown'),
                                    'path': share.get('Path', 'Unknown'),
                                    'issue': 'KMS encryption not enabled'
                                }
                            }
                        
                        findings.append(finding)
                        
                except Exception as nfs_error:
                    logger.warning(f"Could not describe NFS file shares for gateway {gateway_id}: {nfs_error}")
                
                # Check SMB file shares
                try:
                    smb_response = storagegateway_client.describe_smb_file_shares(
                        GatewayARN=gateway_arn
                    )
                    smb_shares = smb_response.get('SMBFileShareInfoList', [])
                    
                    for share in smb_shares:
                        share_arn = share.get('FileShareARN', 'Unknown')
                        share_id = share.get('FileShareId', 'Unknown')
                        kms_encrypted = share.get('KMSEncrypted', False)
                        kms_key = share.get('KMSKey', '')
                        
                        if kms_encrypted:
                            # SMB share is encrypted - COMPLIANT
                            finding = {
                                'region': region,
                                'profile': profile,
                                'resource_type': 'StorageGateway_SMB_FileShare',
                                'resource_id': f"{share_id} ({gateway_name})",
                                'status': 'COMPLIANT',
                                'compliance_status': 'PASS',
                                'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                                'recommendation': COMPLIANCE_DATA.get('recommendation', 'Maintain encryption settings'),
                                'details': {
                                    'file_share_arn': share_arn,
                                    'file_share_id': share_id,
                                    'gateway_name': gateway_name,
                                    'gateway_id': gateway_id,
                                    'share_type': 'SMB',
                                    'kms_encrypted': True,
                                    'kms_key': kms_key,
                                    'location_arn': share.get('LocationARN', 'Unknown'),
                                    'path': share.get('Path', 'Unknown')
                                }
                            }
                        else:
                            # SMB share is not encrypted - NON_COMPLIANT
                            finding = {
                                'region': region,
                                'profile': profile,
                                'resource_type': 'StorageGateway_SMB_FileShare',
                                'resource_id': f"{share_id} ({gateway_name})",
                                'status': 'NON_COMPLIANT',
                                'compliance_status': 'FAIL',
                                'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                                'recommendation': 'Enable KMS encryption for this SMB file share',
                                'details': {
                                    'file_share_arn': share_arn,
                                    'file_share_id': share_id,
                                    'gateway_name': gateway_name,
                                    'gateway_id': gateway_id,
                                    'share_type': 'SMB',
                                    'kms_encrypted': False,
                                    'location_arn': share.get('LocationARN', 'Unknown'),
                                    'path': share.get('Path', 'Unknown'),
                                    'issue': 'KMS encryption not enabled'
                                }
                            }
                        
                        findings.append(finding)
                        
                except Exception as smb_error:
                    logger.warning(f"Could not describe SMB file shares for gateway {gateway_id}: {smb_error}")
                
            except Exception as gateway_error:
                logger.error(f"Error checking file shares for gateway {gateway_id}: {gateway_error}")
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'StorageGateway_FileShare',
                    'resource_id': f"{gateway_name} ({gateway_id})",
                    'status': 'ERROR',
                    'compliance_status': 'ERROR',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                    'recommendation': 'Review Storage Gateway configuration',
                    'error': str(gateway_error),
                    'details': {
                        'gateway_name': gateway_name,
                        'gateway_id': gateway_id,
                        'gateway_type': gateway_type
                    }
                }
                findings.append(finding)
        
    except Exception as e:
        logger.error(f"Error in storagegateway_fileshare_encryption_enabled check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'StorageGateway_FileShare',
            'status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Review Storage Gateway configuration'),
            'error': str(e)
        })
        
    return findings

def storagegateway_fileshare_encryption_enabled(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=storagegateway_fileshare_encryption_enabled_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = storagegateway_fileshare_encryption_enabled(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

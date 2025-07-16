#!/usr/bin/env python3
"""
iso27001_2022_aws - ssm_documents_set_as_public

Principles for engineering secure systems should be established, documented, maintained and applied to any information system development activities.
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
                    'recommendation': entry.get('Recommendation', 'Set SSM documents to private to prevent unauthorized access')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'iso27001_2022_aws',
        'function_name': 'ssm_documents_set_as_public',
        'id': 'ISO27001_SSM_PUBLIC',
        'name': 'SSM Documents Public Access Check',
        'description': 'Principles for engineering secure systems should be established, documented, maintained and applied to any information system development activities.',
        'api_function': 'client=boto3.client(\'ssm\')',
        'user_function': 'list_documents(), describe_document()',
        'risk_level': 'HIGH',
        'recommendation': 'Set SSM documents to private to prevent unauthorized access'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('ssm_documents_set_as_public')

def ssm_documents_set_as_public_check(ssm_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for ssm_documents_set_as_public.
    
    Args:
        ssm_client: Boto3 SSM client (auto-created by framework)
        region (str): AWS region (auto-managed by framework)
        profile (str): AWS profile name (auto-managed by framework)
        logger: Logger instance (auto-configured by framework)
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    try:
        # Get all documents (both owned and public)
        paginator = ssm_client.get_paginator('list_documents')
        
        # Check documents owned by the account
        for page in paginator.paginate(
            Filters=[
                {
                    'Key': 'Owner',
                    'Values': ['Self']
                }
            ]
        ):
            documents = page.get('DocumentIdentifiers', [])
            
            for document in documents:
                document_name = document.get('Name', '')
                document_type = document.get('DocumentType', '')
                
                try:
                    # Get document details including permissions
                    document_response = ssm_client.describe_document(
                        Name=document_name
                    )
                    
                    document_details = document_response.get('Document', {})
                    
                    # Check document permissions
                    try:
                        permissions_response = ssm_client.describe_document_permission(
                            Name=document_name,
                            PermissionType='Share'
                        )
                        
                        account_ids = permissions_response.get('AccountIds', [])
                        account_sharing_info_list = permissions_response.get('AccountSharingInfoList', [])
                        
                        # Check if document is shared publicly
                        is_public = False
                        public_details = []
                        
                        # Check for 'all' in account IDs (indicates public sharing)
                        if 'all' in account_ids:
                            is_public = True
                            public_details.append('Document shared with "all" accounts')
                        
                        # Check account sharing info for public access
                        for sharing_info in account_sharing_info_list:
                            account_id = sharing_info.get('AccountId', '')
                            if account_id == 'all':
                                is_public = True
                                public_details.append('Document explicitly shared with all accounts')
                        
                    except ssm_client.exceptions.InvalidDocumentOperation:
                        # Document doesn't support sharing or no permissions set
                        is_public = False
                        public_details = ['Document does not support sharing or no permissions configured']
                    except Exception as perm_error:
                        logger.warning(f"Could not check permissions for document {document_name}: {perm_error}")
                        is_public = False
                        public_details = [f'Permission check error: {str(perm_error)}']
                    
                    finding = {
                        'region': region,
                        'profile': profile,
                        'resource_type': 'SSMDocument',
                        'resource_id': document_name,
                        'status': 'NON_COMPLIANT' if is_public else 'COMPLIANT',
                        'compliance_status': 'FAIL' if is_public else 'PASS',
                        'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                        'recommendation': COMPLIANCE_DATA.get('recommendation', 'Set SSM documents to private'),
                        'details': {
                            'document_name': document_name,
                            'document_type': document_type,
                            'is_public': is_public,
                            'public_access_details': public_details,
                            'document_format': document_details.get('DocumentFormat', ''),
                            'document_version': document_details.get('DocumentVersion', ''),
                            'status': document_details.get('Status', ''),
                            'created_date': str(document_details.get('CreatedDate', '')),
                            'owner': document.get('Owner', '')
                        }
                    }
                    
                    findings.append(finding)
                    
                    if is_public:
                        logger.warning(f"SSM document {document_name} is set as public: {public_details}")
                    else:
                        logger.info(f"SSM document {document_name} is properly secured (not public)")
                        
                except Exception as doc_error:
                    logger.error(f"Error checking document {document_name}: {doc_error}")
                    findings.append({
                        'region': region,
                        'profile': profile,
                        'resource_type': 'SSMDocument',
                        'resource_id': document_name,
                        'status': 'ERROR',
                        'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                        'recommendation': COMPLIANCE_DATA.get('recommendation', 'Set SSM documents to private'),
                        'error': str(doc_error)
                    })
        
        if not findings:
            logger.info(f"No custom SSM documents found in region {region}")
        
    except Exception as e:
        logger.error(f"Error in ssm_documents_set_as_public check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'SSMDocument',
            'status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Set SSM documents to private'),
            'error': str(e)
        })
        
    return findings

def ssm_documents_set_as_public(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=ssm_documents_set_as_public_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = ssm_documents_set_as_public(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

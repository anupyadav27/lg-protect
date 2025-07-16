#!/usr/bin/env python3
"""
iso27001_2022_aws - kinesis_stream_encrypted_at_rest

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
                    'risk_level': entry.get('Risk Level', 'HIGH'),
                    'recommendation': entry.get('Recommendation', 'Enable encryption at rest for Kinesis streams')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'iso27001_2022_aws',
        'function_name': 'kinesis_stream_encrypted_at_rest',
        'id': 'A.10.1.1',
        'name': 'Cryptographic Controls',
        'description': 'Rules for the effective use of cryptography, including cryptographic key management, should be defined and implemented.',
        'api_function': 'client = boto3.client("kinesis")',
        'user_function': 'list_streams(), describe_stream()',
        'risk_level': 'HIGH',
        'recommendation': 'Enable encryption at rest for Kinesis streams'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('kinesis_stream_encrypted_at_rest')

def kinesis_stream_encrypted_at_rest_check(kinesis_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for kinesis_stream_encrypted_at_rest.
    
    Args:
        kinesis_client: Boto3 Kinesis client (auto-created by framework)
        region (str): AWS region (auto-managed by framework)
        profile (str): AWS profile name (auto-managed by framework)
        logger: Logger instance (auto-configured by framework)
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    try:
        logger.info("Checking Kinesis streams for encryption at rest...")
        
        # Get all Kinesis streams
        response = kinesis_client.list_streams()
        stream_names = response.get('StreamNames', [])
        
        if not stream_names:
            logger.info("No Kinesis streams found in this region")
            return findings
        
        for stream_name in stream_names:
            try:
                # Get detailed stream information
                stream_details = kinesis_client.describe_stream(StreamName=stream_name)
                stream_description = stream_details.get('StreamDescription', {})
                
                stream_status = stream_description.get('StreamStatus', 'Unknown')
                stream_arn = stream_description.get('StreamARN', 'Unknown')
                encryption_type = stream_description.get('EncryptionType', 'NONE')
                key_id = stream_description.get('KeyId', None)
                
                # Check encryption status
                if encryption_type == 'NONE':
                    status = 'NON_COMPLIANT'
                    compliance_status = 'FAIL'
                    message = "Kinesis stream does not have encryption at rest enabled"
                elif encryption_type == 'KMS':
                    status = 'COMPLIANT'
                    compliance_status = 'PASS'
                    message = f"Kinesis stream has KMS encryption enabled with key: {key_id}"
                else:
                    status = 'NON_COMPLIANT'
                    compliance_status = 'FAIL'
                    message = f"Kinesis stream has unknown encryption type: {encryption_type}"
                
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'Kinesis Stream',
                    'resource_id': stream_name,
                    'status': status,
                    'compliance_status': compliance_status,
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable encryption at rest for Kinesis streams'),
                    'details': {
                        'stream_name': stream_name,
                        'stream_arn': stream_arn,
                        'stream_status': stream_status,
                        'encryption_type': encryption_type,
                        'kms_key_id': key_id if key_id else 'Not configured',
                        'creation_timestamp': str(stream_description.get('StreamCreationTimestamp', 'Unknown')),
                        'retention_period_hours': stream_description.get('RetentionPeriodHours', 'Unknown'),
                        'shard_count': len(stream_description.get('Shards', [])),
                        'message': message
                    }
                }
                
                findings.append(finding)
                
            except Exception as e:
                logger.error(f"Error describing stream {stream_name}: {e}")
                findings.append({
                    'region': region,
                    'profile': profile,
                    'resource_type': 'Kinesis Stream',
                    'resource_id': stream_name,
                    'status': 'ERROR',
                    'compliance_status': 'ERROR',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable encryption at rest for Kinesis streams'),
                    'error': str(e),
                    'details': {
                        'stream_name': stream_name,
                        'error_message': str(e)
                    }
                })
            
    except Exception as e:
        logger.error(f"Error in kinesis_stream_encrypted_at_rest check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'Kinesis Stream',
            'resource_id': 'Unknown',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable encryption at rest for Kinesis streams'),
            'error': str(e),
            'details': {
                'error_message': str(e),
                'check_type': 'kinesis_stream_encrypted_at_rest'
            }
        })
        
    return findings

def kinesis_stream_encrypted_at_rest(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=kinesis_stream_encrypted_at_rest_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = kinesis_stream_encrypted_at_rest(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

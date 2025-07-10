#!/usr/bin/env python3
"""
kisa_isms_p_2023_korean_aws - kinesis_stream_data_retention_period

서버, 응용프로그램, 보안시스템, 네트워크시스템 등 정보시스템에 대한 사용자 접속기록, 시스템로그, 권한부여 내역 등의 로그유형, 보존기간, 보존방법 등을 정하고 위·변조, 도난, 분실되지 않도록 안전하게 보존·관리하여야 한다.
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
                    'recommendation': entry.get('Recommendation', 'Configure appropriate data retention period for Kinesis streams')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'kisa_isms_p_2023_korean_aws',
        'function_name': 'kinesis_stream_data_retention_period',
        'id': '3.4.5',
        'name': 'Log Management',
        'description': '서버, 응용프로그램, 보안시스템, 네트워크시스템 등 정보시스템에 대한 사용자 접속기록, 시스템로그, 권한부여 내역 등의 로그유형, 보존기간, 보존방법 등을 정하고 위·변조, 도난, 분실되지 않도록 안전하게 보존·관리하여야 한다.',
        'api_function': 'client = boto3.client("kinesis")',
        'user_function': 'list_streams(), describe_stream()',
        'risk_level': 'MEDIUM',
        'recommendation': 'Configure appropriate data retention period for Kinesis streams'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('kinesis_stream_data_retention_period')

def kinesis_stream_data_retention_period_check(kinesis_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for kinesis_stream_data_retention_period.
    
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
        logger.info("Checking Kinesis streams for data retention period configuration...")
        
        # Get all Kinesis streams
        response = kinesis_client.list_streams()
        stream_names = response.get('StreamNames', [])
        
        if not stream_names:
            logger.info("No Kinesis streams found in this region")
            return findings
        
        # Define minimum retention period requirements (e.g., 7 days minimum)
        minimum_retention_hours = 24 * 7  # 7 days
        recommended_retention_hours = 24 * 30  # 30 days
        
        for stream_name in stream_names:
            try:
                # Get detailed stream information
                stream_details = kinesis_client.describe_stream(StreamName=stream_name)
                stream_description = stream_details.get('StreamDescription', {})
                
                stream_status = stream_description.get('StreamStatus', 'Unknown')
                stream_arn = stream_description.get('StreamARN', 'Unknown')
                retention_period_hours = stream_description.get('RetentionPeriodHours', 24)  # Default is 24 hours
                
                # Check retention period compliance
                if retention_period_hours < minimum_retention_hours:
                    status = 'NON_COMPLIANT'
                    compliance_status = 'FAIL'
                    message = f"Kinesis stream retention period ({retention_period_hours} hours) is below minimum requirement ({minimum_retention_hours} hours)"
                elif retention_period_hours < recommended_retention_hours:
                    status = 'COMPLIANT'
                    compliance_status = 'PASS'
                    message = f"Kinesis stream retention period ({retention_period_hours} hours) meets minimum but is below recommended period ({recommended_retention_hours} hours)"
                else:
                    status = 'COMPLIANT'
                    compliance_status = 'PASS'
                    message = f"Kinesis stream retention period ({retention_period_hours} hours) meets recommended requirements"
                
                finding = {
                    'region': region,
                    'profile': profile,
                    'resource_type': 'Kinesis Stream',
                    'resource_id': stream_name,
                    'status': status,
                    'compliance_status': compliance_status,
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Configure appropriate data retention period for Kinesis streams'),
                    'details': {
                        'stream_name': stream_name,
                        'stream_arn': stream_arn,
                        'stream_status': stream_status,
                        'retention_period_hours': retention_period_hours,
                        'retention_period_days': round(retention_period_hours / 24, 1),
                        'minimum_required_hours': minimum_retention_hours,
                        'recommended_hours': recommended_retention_hours,
                        'creation_timestamp': str(stream_description.get('StreamCreationTimestamp', 'Unknown')),
                        'shard_count': len(stream_description.get('Shards', [])),
                        'encryption_type': stream_description.get('EncryptionType', 'NONE'),
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
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Configure appropriate data retention period for Kinesis streams'),
                    'error': str(e),
                    'details': {
                        'stream_name': stream_name,
                        'error_message': str(e)
                    }
                })
            
    except Exception as e:
        logger.error(f"Error in kinesis_stream_data_retention_period check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'Kinesis Stream',
            'resource_id': 'Unknown',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'MEDIUM'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Configure appropriate data retention period for Kinesis streams'),
            'error': str(e),
            'details': {
                'error_message': str(e),
                'check_type': 'kinesis_stream_data_retention_period'
            }
        })
        
    return findings

def kinesis_stream_data_retention_period(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=kinesis_stream_data_retention_period_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = kinesis_stream_data_retention_period(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

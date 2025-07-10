#!/usr/bin/env python3
"""
cis_4.0_aws - rds_instance_storage_encrypted

Ensure that encryption-at-rest is enabled for RDS instances
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
        'compliance_name': 'cis_4.0_aws',
        'function_name': 'rds_instance_storage_encrypted',
        'id': '2.3.1',
        'name': 'Ensure that encryption-at-rest is enabled for RDS instances',
        'description': 'Ensure that encryption-at-rest is enabled for RDS instances',
        'api_function': 'client = boto3.client("rds")',
        'user_function': 'describe_db_instances()',
        'risk_level': 'HIGH',
        'recommendation': 'Enable encryption-at-rest for RDS instances to protect sensitive data'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('rds_instance_storage_encrypted')

def rds_instance_storage_encrypted_check(rds_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for rds_instance_storage_encrypted.
    
    Args:
        rds_client: Boto3 RDS client (auto-created by framework)
        region (str): AWS region (auto-managed by framework)
        profile (str): AWS profile name (auto-managed by framework)
        logger: Logger instance (auto-configured by framework)
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    try:
        logger.info(f"Checking RDS instances for storage encryption in region {region}")
        
        # Get all RDS instances
        db_instances_response = rds_client.describe_db_instances()
        db_instances = db_instances_response.get('DBInstances', [])
        
        if not db_instances:
            logger.info(f"No RDS instances found in region {region}")
            return findings
        
        # Check each RDS instance for encryption
        for db_instance in db_instances:
            db_instance_identifier = db_instance.get('DBInstanceIdentifier', 'unknown')
            storage_encrypted = db_instance.get('StorageEncrypted', False)
            
            try:
                if storage_encrypted:
                    # Compliant: RDS instance has storage encryption enabled
                    finding = {
                        'region': region,
                        'profile': profile,
                        'resource_type': 'RDS Instance',
                        'resource_id': db_instance_identifier,
                        'status': 'COMPLIANT',
                        'compliance_status': 'PASS',
                        'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                        'recommendation': COMPLIANCE_DATA.get('recommendation', 'RDS instance properly encrypted'),
                        'details': {
                            'db_instance_identifier': db_instance_identifier,
                            'storage_encrypted': storage_encrypted,
                            'kms_key_id': db_instance.get('KmsKeyId', 'default'),
                            'engine': db_instance.get('Engine', 'unknown'),
                            'engine_version': db_instance.get('EngineVersion', 'unknown'),
                            'db_instance_class': db_instance.get('DBInstanceClass', 'unknown'),
                            'allocated_storage': db_instance.get('AllocatedStorage', 0),
                            'storage_type': db_instance.get('StorageType', 'unknown'),
                            'multi_az': db_instance.get('MultiAZ', False),
                            'availability_zone': db_instance.get('AvailabilityZone', 'unknown')
                        }
                    }
                else:
                    # Non-compliant: RDS instance does not have storage encryption enabled
                    finding = {
                        'region': region,
                        'profile': profile,
                        'resource_type': 'RDS Instance',
                        'resource_id': db_instance_identifier,
                        'status': 'NON_COMPLIANT',
                        'compliance_status': 'FAIL',
                        'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                        'recommendation': COMPLIANCE_DATA.get('recommendation', 'Enable encryption-at-rest for RDS instance'),
                        'details': {
                            'db_instance_identifier': db_instance_identifier,
                            'storage_encrypted': storage_encrypted,
                            'issue': 'RDS instance does not have storage encryption enabled',
                            'engine': db_instance.get('Engine', 'unknown'),
                            'engine_version': db_instance.get('EngineVersion', 'unknown'),
                            'db_instance_class': db_instance.get('DBInstanceClass', 'unknown'),
                            'allocated_storage': db_instance.get('AllocatedStorage', 0),
                            'storage_type': db_instance.get('StorageType', 'unknown'),
                            'multi_az': db_instance.get('MultiAZ', False),
                            'availability_zone': db_instance.get('AvailabilityZone', 'unknown'),
                            'security_risk': 'Data stored without encryption is vulnerable to unauthorized access',
                            'remediation_note': 'Encryption cannot be enabled on existing instances. Create encrypted snapshot and restore to new encrypted instance.'
                        }
                    }
                
                findings.append(finding)
                
            except Exception as e:
                logger.error(f"Error checking RDS instance {db_instance_identifier} in {region}: {e}")
                findings.append({
                    'region': region,
                    'profile': profile,
                    'resource_type': 'RDS Instance',
                    'resource_id': db_instance_identifier,
                    'status': 'ERROR',
                    'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                    'recommendation': COMPLIANCE_DATA.get('recommendation', 'Review and remediate as needed'),
                    'error': str(e)
                })
        
    except Exception as e:
        logger.error(f"Error in rds_instance_storage_encrypted check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'RDS Instance',
            'status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Review and remediate as needed'),
            'error': str(e)
        })
        
    return findings

def rds_instance_storage_encrypted(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=rds_instance_storage_encrypted_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = rds_instance_storage_encrypted(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

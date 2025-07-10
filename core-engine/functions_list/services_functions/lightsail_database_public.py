#!/usr/bin/env python3
"""
aws_foundational_security_best_practices_aws - lightsail_database_public

This control checks whether Lightsail databases have public accessibility disabled for security.
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
                    'recommendation': entry.get('Recommendation', 'Disable public accessibility for Lightsail databases')
                }
    except Exception as e:
        print(f"Warning: Could not load compliance metadata: {e}")
        
    # Return default structure if JSON loading fails
    return {
        'compliance_name': 'aws_foundational_security_best_practices_aws',
        'function_name': 'lightsail_database_public',
        'id': 'Lightsail.4',
        'name': 'Lightsail databases should not be publicly accessible',
        'description': 'This control checks whether Lightsail databases have public accessibility disabled for security.',
        'api_function': 'client = boto3.client("lightsail")',
        'user_function': 'get_relational_databases()',
        'risk_level': 'HIGH',
        'recommendation': 'Disable public accessibility for Lightsail databases'
    }

# Load compliance metadata for this specific function
COMPLIANCE_DATA = load_compliance_metadata('lightsail_database_public')

def lightsail_database_public_check(lightsail_client, region: str, profile: str, logger) -> List[Dict[str, Any]]:
    """
    Perform the actual compliance check for lightsail_database_public.
    
    Args:
        lightsail_client: Boto3 Lightsail client (auto-created by framework)
        region (str): AWS region (auto-managed by framework)
        profile (str): AWS profile name (auto-managed by framework)
        logger: Logger instance (auto-configured by framework)
        
    Returns:
        List[Dict[str, Any]]: List of compliance findings
    """
    findings = []
    
    try:
        logger.info("Checking Lightsail databases for public accessibility...")
        
        # Get all relational databases
        response = lightsail_client.get_relational_databases()
        databases = response.get('relationalDatabases', [])
        
        if not databases:
            logger.info("No Lightsail databases found in this region")
            return findings
        
        for database in databases:
            db_name = database.get('name', 'Unknown')
            db_state = database.get('state', 'Unknown')
            
            # Check public accessibility
            publicly_accessible = database.get('publiclyAccessible', False)
            
            # Get database connection details
            endpoint = database.get('masterEndpoint', {})
            endpoint_address = endpoint.get('address', 'Unknown')
            endpoint_port = endpoint.get('port', 'Unknown')
            
            # Determine compliance status
            if publicly_accessible:
                status = 'NON_COMPLIANT'
                compliance_status = 'FAIL'
                message = "Database is configured to be publicly accessible"
            else:
                status = 'COMPLIANT'
                compliance_status = 'PASS'
                message = "Database is not publicly accessible"
            
            finding = {
                'region': region,
                'profile': profile,
                'resource_type': 'Lightsail Database',
                'resource_id': db_name,
                'status': status,
                'compliance_status': compliance_status,
                'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
                'recommendation': COMPLIANCE_DATA.get('recommendation', 'Disable public accessibility for Lightsail databases'),
                'details': {
                    'database_name': db_name,
                    'database_state': db_state,
                    'publicly_accessible': publicly_accessible,
                    'endpoint_address': endpoint_address,
                    'endpoint_port': endpoint_port,
                    'engine': database.get('engine', 'Unknown'),
                    'engine_version': database.get('engineVersion', 'Unknown'),
                    'blueprint_id': database.get('relationalDatabaseBlueprintId', 'Unknown'),
                    'bundle_id': database.get('relationalDatabaseBundleId', 'Unknown'),
                    'backup_retention_enabled': database.get('backupRetentionEnabled', False),
                    'created_at': str(database.get('createdAt', 'Unknown')),
                    'location': database.get('location', {}).get('availabilityZone', 'Unknown'),
                    'message': message
                }
            }
            
            findings.append(finding)
            
    except Exception as e:
        logger.error(f"Error in lightsail_database_public check for {region}: {e}")
        findings.append({
            'region': region,
            'profile': profile,
            'resource_type': 'Lightsail Database',
            'resource_id': 'Unknown',
            'status': 'ERROR',
            'compliance_status': 'ERROR',
            'risk_level': COMPLIANCE_DATA.get('risk_level', 'HIGH'),
            'recommendation': COMPLIANCE_DATA.get('recommendation', 'Disable public accessibility for Lightsail databases'),
            'error': str(e),
            'details': {
                'error_message': str(e),
                'check_type': 'lightsail_database_public'
            }
        })
        
    return findings

def lightsail_database_public(profile_name: str = None, region_name: str = None) -> Dict[str, Any]:
    """Main compliance check function."""
    engine = ComplianceEngine(COMPLIANCE_DATA)
    return engine.run_compliance_check(
        check_function=lightsail_database_public_check,
        profile_name=profile_name,
        region_name=region_name
    )

if __name__ == "__main__":
    # Set up command line interface
    args = setup_command_line_interface(COMPLIANCE_DATA)
    
    # Run the compliance check
    results = lightsail_database_public(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Save results and exit
    save_results(results, args.output, args.verbose)
    exit_with_status(results)

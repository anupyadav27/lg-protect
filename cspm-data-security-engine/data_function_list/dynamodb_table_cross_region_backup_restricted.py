#!/usr/bin/env python3
"""
data_security_aws - dynamodb_table_cross_region_backup_restricted

Ensure DynamoDB cross-region backups are only configured to approved regions that meet data residency requirements.
"""

# Rule Metadata from YAML:
# Function Name: dynamodb_table_cross_region_backup_restricted
# Capability: DATA_RESIDENCY
# Service: DYNAMODB
# Subservice: BACKUP
# Description: Ensure DynamoDB cross-region backups are only configured to approved regions that meet data residency requirements.
# Risk Level: HIGH
# Recommendation: Restrict cross-region backup destinations
# API Function: client = boto3.client('dynamodb')
# User Function: dynamodb_table_cross_region_backup_restricted()

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
        "function_name": "dynamodb_table_cross_region_backup_restricted",
        "title": "Restrict cross-region backup destinations",
        "description": "Ensure DynamoDB cross-region backups are only configured to approved regions that meet data residency requirements.",
        "capability": "data_residency",
        "service": "dynamodb",
        "subservice": "backup",
        "risk": "HIGH",
        "existing": False
    }

def dynamodb_table_cross_region_backup_restricted_check(region_name: str, profile_name: str = None) -> List[Dict[str, Any]]:
    """
    Check dynamodb resources for data_residency compliance.
    
    Args:
        region_name (str): AWS region name
        profile_name (str): AWS profile name (optional)
        
    Returns:
        List[Dict]: List of compliance findings
    """
    findings = []
    approved_regions = ["us-east-1", "us-west-2"]  # Example approved regions

    try:
        # Initialize boto3 client
        session = boto3.Session(profile_name=profile_name)
        dynamodb_client = session.client('dynamodb', region_name=region_name)

        logger.info(f"Checking DynamoDB resources for data residency compliance in region {region_name}")

        # Example logic for compliance check
        paginator = dynamodb_client.get_paginator('list_backups')
        for page in paginator.paginate():
            for backup in page.get('BackupSummaries', []):
                backup_arn = backup.get('BackupArn')
                backup_region = backup_arn.split(":")[3]  # Extract region from ARN

                if backup_region not in approved_regions:
                    findings.append({
                        "region": region_name,
                        "profile": profile_name or "default",
                        "resource_type": "dynamodb_backup",
                        "resource_id": backup_arn,
                        "status": "NON_COMPLIANT",
                        "risk_level": "HIGH",
                        "recommendation": "Restrict cross-region backup destinations",
                        "details": {
                            "dynamodb_id": backup_arn,
                            "violation": f"Backup configured in unapproved region: {backup_region}"
                        }
                    })
                else:
                    findings.append({
                        "region": region_name,
                        "profile": profile_name or "default",
                        "resource_type": "dynamodb_backup",
                        "resource_id": backup_arn,
                        "status": "COMPLIANT",
                        "risk_level": "HIGH",
                        "recommendation": "Resource is compliant",
                        "details": {
                            "dynamodb_id": backup_arn
                        }
                    })

        logger.info(f"Completed checking DynamoDB cross-region backups. Found {len(findings)} findings.")

    except Exception as e:
        logger.error(f"Failed to check DynamoDB cross-region backups: {e}")
        findings.append({
            "region": region_name,
            "profile": profile_name or "default",
            "resource_type": "dynamodb_backup",
            "resource_id": "unknown",
            "status": "ERROR",
            "risk_level": "HIGH",
            "recommendation": "Fix API access issues",
            "details": {
                "error": str(e)
            }
        })

    return findings

def dynamodb_table_cross_region_backup_restricted(region_name: str, profile_name: str = None) -> Dict[str, Any]:
    """
    Main function wrapper for dynamodb_table_cross_region_backup_restricted.
    
    Args:
        region_name (str): AWS region name
        profile_name (str): AWS profile name (optional)
        
    Returns:
        Dict: Results summary
    """
    COMPLIANCE_DATA = load_rule_metadata("dynamodb_table_cross_region_backup_restricted")
    
    # TODO: Implement SecurityEngine integration when available
    # from data_security_engine import SecurityEngine
    # engine = SecurityEngine(COMPLIANCE_DATA)
    # return engine.run_check(region_name, profile_name, dynamodb_table_cross_region_backup_restricted_check)
    
    # Current implementation
    findings = dynamodb_table_cross_region_backup_restricted_check(region_name, profile_name)
    
    # Calculate compliance statistics
    total_findings = len(findings)
    compliant_findings = len([f for f in findings if f['status'] == 'COMPLIANT'])
    non_compliant_findings = len([f for f in findings if f['status'] == 'NON_COMPLIANT'])
    error_findings = len([f for f in findings if f['status'] == 'ERROR'])
    
    return {
        "function_name": "dynamodb_table_cross_region_backup_restricted",
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
    """CLI entry point for dynamodb_table_cross_region_backup_restricted."""
    # TODO: Implement setup_command_line_interface() when data_security_engine is available
    # from data_security_engine import setup_command_line_interface, save_results, exit_with_status
    # args = setup_command_line_interface()
    # results = dynamodb_table_cross_region_backup_restricted(args.region, args.profile)
    # save_results(results, args.output_file)
    # exit_with_status(results)
    
    # Current CLI implementation
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Ensure DynamoDB cross-region backups are only configured to approved regions that meet data residency requirements."
    )
    parser.add_argument("--region", default="us-east-1", help="AWS region")
    parser.add_argument("--profile", help="AWS profile name")
    parser.add_argument("--output", help="Output file for results (JSON format)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        results = dynamodb_table_cross_region_backup_restricted(args.region, args.profile)
        
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

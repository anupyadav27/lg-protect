#!/usr/bin/env python3
"""
data_security_aws - vpc_flow_logs_encryption_enabled

Ensure VPC Flow Logs are encrypted to protect network traffic data from unauthorized access.
"""

# Rule Metadata from YAML:
# Function Name: vpc_flow_logs_encryption_enabled
# Capability: DATA_PROTECTION
# Service: VPC
# Subservice: ENCRYPTION
# Description: Ensure VPC Flow Logs are encrypted to protect network traffic data from unauthorized access.
# Risk Level: MEDIUM
# Recommendation: Enable encryption for VPC Flow Logs
# API Function: client = boto3.client('vpc')
# User Function: vpc_flow_logs_encryption_enabled()

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
        "function_name": "vpc_flow_logs_encryption_enabled",
        "title": "Enable encryption for VPC Flow Logs",
        "description": "Ensure VPC Flow Logs are encrypted to protect network traffic data from unauthorized access.",
        "capability": "data_protection",
        "service": "vpc",
        "subservice": "encryption",
        "risk": "MEDIUM",
        "existing": False
    }

def vpc_flow_logs_encryption_enabled_check(region_name: str, profile_name: str = None) -> List[Dict[str, Any]]:
    """
    Check VPC Flow Logs for encryption compliance.
    
    Args:
        region_name (str): AWS region name
        profile_name (str): AWS profile name (optional)
        
    Returns:
        List[Dict]: List of compliance findings
    """
    findings = []
    
    try:
        # Initialize boto3 clients
        session = boto3.Session(profile_name=profile_name)
        ec2_client = session.client('ec2', region_name=region_name)
        logs_client = session.client('logs', region_name=region_name)
        
        logger.info(f"Checking VPC Flow Logs encryption compliance in region {region_name}")
        
        # Get all VPCs in the region
        vpcs_response = ec2_client.describe_vpcs()
        vpcs = vpcs_response.get('Vpcs', [])
        
        for vpc in vpcs:
            vpc_id = vpc.get('VpcId')
            vpc_state = vpc.get('State')
            
            if vpc_state != 'available':
                continue
                
            try:
                # Check for flow logs on this VPC
                flow_logs_response = ec2_client.describe_flow_logs(
                    Filters=[
                        {
                            'Name': 'resource-id',
                            'Values': [vpc_id]
                        }
                    ]
                )
                
                flow_logs = flow_logs_response.get('FlowLogs', [])
                
                if not flow_logs:
                    # No flow logs configured for this VPC
                    findings.append({
                        "region": region_name,
                        "profile": profile_name or "default",
                        "resource_type": "vpc_flow_logs",
                        "resource_id": vpc_id,
                        "status": "NON_COMPLIANT",
                        "risk_level": "MEDIUM",
                        "recommendation": "Enable VPC Flow Logs with encryption for network traffic monitoring",
                        "details": {
                            "vpc_id": vpc_id,
                            "vpc_state": vpc_state,
                            "violation": "No VPC Flow Logs configured",
                            "cidr_block": vpc.get('CidrBlock')
                        }
                    })
                    continue
                
                # Check each flow log for encryption
                for flow_log in flow_logs:
                    flow_log_id = flow_log.get('FlowLogId')
                    flow_log_status = flow_log.get('FlowLogStatus')
                    destination_type = flow_log.get('LogDestinationType')
                    
                    if flow_log_status != 'ACTIVE':
                        continue
                    
                    is_encrypted = False
                    encryption_details = {}
                    
                    if destination_type == 'cloud-watch-logs':
                        # Check CloudWatch Logs encryption
                        log_group_name = flow_log.get('LogGroupName')
                        if log_group_name:
                            try:
                                log_group_response = logs_client.describe_log_groups(
                                    logGroupNamePrefix=log_group_name
                                )
                                log_groups = log_group_response.get('logGroups', [])
                                
                                for log_group in log_groups:
                                    if log_group.get('logGroupName') == log_group_name:
                                        kms_key_id = log_group.get('kmsKeyId')
                                        if kms_key_id:
                                            is_encrypted = True
                                            encryption_details = {
                                                "destination_type": "cloudwatch-logs",
                                                "log_group": log_group_name,
                                                "kms_key_id": kms_key_id
                                            }
                                        break
                                        
                            except Exception as log_error:
                                logger.warning(f"Failed to check CloudWatch log group {log_group_name}: {log_error}")
                                
                    elif destination_type == 's3':
                        # For S3 destinations, check if the S3 bucket has encryption
                        destination_options = flow_log.get('DestinationOptions', {})
                        s3_bucket = destination_options.get('S3BucketName')
                        
                        if s3_bucket:
                            try:
                                s3_client = session.client('s3', region_name=region_name)
                                
                                # Check bucket encryption
                                try:
                                    encryption_response = s3_client.get_bucket_encryption(Bucket=s3_bucket)
                                    encryption_rules = encryption_response.get('ServerSideEncryptionConfiguration', {}).get('Rules', [])
                                    
                                    if encryption_rules:
                                        is_encrypted = True
                                        encryption_details = {
                                            "destination_type": "s3",
                                            "s3_bucket": s3_bucket,
                                            "encryption_rules_count": len(encryption_rules)
                                        }
                                        
                                except s3_client.exceptions.ClientError as s3_error:
                                    if s3_error.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                                        encryption_details = {
                                            "destination_type": "s3",
                                            "s3_bucket": s3_bucket,
                                            "encryption_status": "not_configured"
                                        }
                                    else:
                                        raise s3_error
                                        
                            except Exception as s3_error:
                                logger.warning(f"Failed to check S3 bucket encryption for {s3_bucket}: {s3_error}")
                    
                    # Record finding based on encryption status
                    if is_encrypted:
                        findings.append({
                            "region": region_name,
                            "profile": profile_name or "default",
                            "resource_type": "vpc_flow_logs",
                            "resource_id": f"{vpc_id}:{flow_log_id}",
                            "status": "COMPLIANT",
                            "risk_level": "MEDIUM",
                            "recommendation": "VPC Flow Logs are properly encrypted",
                            "details": {
                                "vpc_id": vpc_id,
                                "flow_log_id": flow_log_id,
                                "flow_log_status": flow_log_status,
                                "destination_type": destination_type,
                                "encryption_details": encryption_details,
                                "cidr_block": vpc.get('CidrBlock')
                            }
                        })
                    else:
                        findings.append({
                            "region": region_name,
                            "profile": profile_name or "default",
                            "resource_type": "vpc_flow_logs",
                            "resource_id": f"{vpc_id}:{flow_log_id}",
                            "status": "NON_COMPLIANT",
                            "risk_level": "MEDIUM",
                            "recommendation": "Enable encryption for VPC Flow Logs to protect network traffic data",
                            "details": {
                                "vpc_id": vpc_id,
                                "flow_log_id": flow_log_id,
                                "flow_log_status": flow_log_status,
                                "destination_type": destination_type,
                                "violation": "VPC Flow Logs are not encrypted",
                                "encryption_details": encryption_details,
                                "cidr_block": vpc.get('CidrBlock')
                            }
                        })
                        
            except Exception as vpc_error:
                logger.warning(f"Failed to check VPC {vpc_id}: {vpc_error}")
                findings.append({
                    "region": region_name,
                    "profile": profile_name or "default",
                    "resource_type": "vpc_flow_logs",
                    "resource_id": vpc_id,
                    "status": "ERROR",
                    "risk_level": "MEDIUM",
                    "recommendation": "Unable to check VPC Flow Logs configuration",
                    "details": {
                        "vpc_id": vpc_id,
                        "error": str(vpc_error)
                    }
                })
        
        logger.info(f"Completed checking vpc_flow_logs_encryption_enabled. Found {len(findings)} findings.")
        
    except Exception as e:
        logger.error(f"Failed to check vpc_flow_logs_encryption_enabled: {e}")
        findings.append({
            "region": region_name,
            "profile": profile_name or "default",
            "resource_type": "vpc_flow_logs",
            "resource_id": "unknown",
            "status": "ERROR",
            "risk_level": "MEDIUM",
            "recommendation": "Fix API access issues",
            "details": {
                "error": str(e)
            }
        })
    
    return findings

def vpc_flow_logs_encryption_enabled(region_name: str, profile_name: str = None) -> Dict[str, Any]:
    """
    Main function wrapper for vpc_flow_logs_encryption_enabled.
    
    Args:
        region_name (str): AWS region name
        profile_name (str): AWS profile name (optional)
        
    Returns:
        Dict: Results summary
    """
    COMPLIANCE_DATA = load_rule_metadata("vpc_flow_logs_encryption_enabled")
    
    # TODO: Implement SecurityEngine integration when available
    # from data_security_engine import SecurityEngine
    # engine = SecurityEngine(COMPLIANCE_DATA)
    # return engine.run_check(region_name, profile_name, vpc_flow_logs_encryption_enabled_check)
    
    # Current implementation
    findings = vpc_flow_logs_encryption_enabled_check(region_name, profile_name)
    
    # Calculate compliance statistics
    total_findings = len(findings)
    compliant_findings = len([f for f in findings if f['status'] == 'COMPLIANT'])
    non_compliant_findings = len([f for f in findings if f['status'] == 'NON_COMPLIANT'])
    error_findings = len([f for f in findings if f['status'] == 'ERROR'])
    
    return {
        "function_name": "vpc_flow_logs_encryption_enabled",
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
    """CLI entry point for vpc_flow_logs_encryption_enabled."""
    # TODO: Implement setup_command_line_interface() when data_security_engine is available
    # from data_security_engine import setup_command_line_interface, save_results, exit_with_status
    # args = setup_command_line_interface()
    # results = vpc_flow_logs_encryption_enabled(args.region, args.profile)
    # save_results(results, args.output_file)
    # exit_with_status(results)
    
    # Current CLI implementation
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Ensure VPC Flow Logs are encrypted to protect network traffic data from unauthorized access."
    )
    parser.add_argument("--region", default="us-east-1", help="AWS region")
    parser.add_argument("--profile", help="AWS profile name")
    parser.add_argument("--output", help="Output file for results (JSON format)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        results = vpc_flow_logs_encryption_enabled(args.region, args.profile)
        
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

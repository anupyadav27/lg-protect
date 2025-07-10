#!/usr/bin/env python3
"""
data_security_aws - ebs_volume_kms_encryption_enabled

Ensure EBS volumes use KMS encryption instead of default encryption for enhanced key management and audit trails.
"""

# Rule Metadata from YAML:
# Function Name: ebs_volume_kms_encryption_enabled
# Capability: DATA_PROTECTION
# Service: EBS
# Subservice: ENCRYPTION
# Description: Ensure EBS volumes use KMS encryption instead of default encryption for enhanced key management and audit trails.
# Risk Level: HIGH
# Recommendation: Use KMS encryption for EBS volumes
# API Function: client = boto3.client('ebs')
# User Function: ebs_volume_kms_encryption_enabled()

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
        "function_name": "ebs_volume_kms_encryption_enabled",
        "title": "Use KMS encryption for EBS volumes",
        "description": "Ensure EBS volumes use KMS encryption instead of default encryption for enhanced key management and audit trails.",
        "capability": "data_protection",
        "service": "ebs",
        "subservice": "encryption",
        "risk": "HIGH",
        "existing": False
    }

def ebs_volume_kms_encryption_enabled_check(region_name: str, profile_name: str = None) -> List[Dict[str, Any]]:
    """
    Check EBS volumes for KMS encryption compliance.
    
    Args:
        region_name (str): AWS region name
        profile_name (str): AWS profile name (optional)
        
    Returns:
        List[Dict]: List of compliance findings
    """
    findings = []
    
    try:
        # Initialize boto3 client
        session = boto3.Session(profile_name=profile_name)
        ec2_client = session.client('ec2', region_name=region_name)
        
        logger.info(f"Checking EBS volumes for KMS encryption compliance in region {region_name}")
        
        # Get all EBS volumes
        paginator = ec2_client.get_paginator('describe_volumes')
        
        for page in paginator.paginate():
            volumes = page.get('Volumes', [])
            
            for volume in volumes:
                volume_id = volume.get('VolumeId')
                volume_arn = f"arn:aws:ec2:{region_name}:{volume.get('OwnerId', 'unknown')}:volume/{volume_id}"
                encrypted = volume.get('Encrypted', False)
                kms_key_id = volume.get('KmsKeyId')
                volume_type = volume.get('VolumeType')
                state = volume.get('State')
                size = volume.get('Size', 0)
                
                # Get volume tags
                tags = {tag['Key']: tag['Value'] for tag in volume.get('Tags', [])}
                
                if not encrypted:
                    findings.append({
                        "region": region_name,
                        "profile": profile_name or "default",
                        "resource_type": "ebs_volume",
                        "resource_id": volume_arn,
                        "status": "NON_COMPLIANT",
                        "risk_level": "HIGH",
                        "recommendation": "Enable KMS encryption for EBS volume",
                        "details": {
                            "volume_id": volume_id,
                            "volume_type": volume_type,
                            "size_gb": size,
                            "state": state,
                            "encrypted": encrypted,
                            "violation": "EBS volume is not encrypted",
                            "tags": tags
                        }
                    })
                elif not kms_key_id:
                    findings.append({
                        "region": region_name,
                        "profile": profile_name or "default",
                        "resource_type": "ebs_volume",
                        "resource_id": volume_arn,
                        "status": "NON_COMPLIANT",
                        "risk_level": "MEDIUM",
                        "recommendation": "Use customer-managed KMS key instead of default AWS managed key",
                        "details": {
                            "volume_id": volume_id,
                            "volume_type": volume_type,
                            "size_gb": size,
                            "state": state,
                            "encrypted": encrypted,
                            "kms_key_id": "default",
                            "violation": "Using default AWS managed encryption key",
                            "tags": tags
                        }
                    })
                else:
                    # Check if using customer-managed key
                    try:
                        kms_client = session.client('kms', region_name=region_name)
                        key_response = kms_client.describe_key(KeyId=kms_key_id)
                        key_metadata = key_response.get('KeyMetadata', {})
                        key_manager = key_metadata.get('KeyManager', 'UNKNOWN')
                        key_usage = key_metadata.get('KeyUsage', 'UNKNOWN')
                        key_state = key_metadata.get('KeyState', 'UNKNOWN')
                        
                        if key_manager == 'CUSTOMER' and key_state == 'Enabled':
                            findings.append({
                                "region": region_name,
                                "profile": profile_name or "default",
                                "resource_type": "ebs_volume",
                                "resource_id": volume_arn,
                                "status": "COMPLIANT",
                                "risk_level": "LOW",
                                "recommendation": "Continue using customer-managed KMS encryption",
                                "details": {
                                    "volume_id": volume_id,
                                    "volume_type": volume_type,
                                    "size_gb": size,
                                    "state": state,
                                    "encrypted": encrypted,
                                    "kms_key_id": kms_key_id,
                                    "key_manager": key_manager,
                                    "key_usage": key_usage,
                                    "key_state": key_state,
                                    "tags": tags
                                }
                            })
                        else:
                            findings.append({
                                "region": region_name,
                                "profile": profile_name or "default",
                                "resource_type": "ebs_volume",
                                "resource_id": volume_arn,
                                "status": "NON_COMPLIANT",
                                "risk_level": "MEDIUM",
                                "recommendation": "Use customer-managed KMS key with proper state",
                                "details": {
                                    "volume_id": volume_id,
                                    "volume_type": volume_type,
                                    "size_gb": size,
                                    "state": state,
                                    "encrypted": encrypted,
                                    "kms_key_id": kms_key_id,
                                    "key_manager": key_manager,
                                    "key_state": key_state,
                                    "violation": f"KMS key is {key_manager} managed and in {key_state} state",
                                    "tags": tags
                                }
                            })
                            
                    except Exception as kms_error:
                        logger.warning(f"Could not describe KMS key {kms_key_id}: {kms_error}")
                        findings.append({
                            "region": region_name,
                            "profile": profile_name or "default",
                            "resource_type": "ebs_volume",
                            "resource_id": volume_arn,
                            "status": "WARNING",
                            "risk_level": "MEDIUM",
                            "recommendation": "Verify KMS key accessibility and permissions",
                            "details": {
                                "volume_id": volume_id,
                                "volume_type": volume_type,
                                "size_gb": size,
                                "state": state,
                                "encrypted": encrypted,
                                "kms_key_id": kms_key_id,
                                "warning": f"Cannot access KMS key details: {kms_error}",
                                "tags": tags
                            }
                        })
        
        logger.info(f"Completed checking EBS KMS encryption. Found {len(findings)} findings.")
        
    except Exception as e:
        logger.error(f"Failed to check EBS KMS encryption: {e}")
        findings.append({
            "region": region_name,
            "profile": profile_name or "default",
            "resource_type": "ebs_volume",
            "resource_id": "unknown",
            "status": "ERROR",
            "risk_level": "HIGH",
            "recommendation": "Fix API access issues",
            "details": {
                "error": str(e)
            }
        })
    
    return findings

def ebs_volume_kms_encryption_enabled(region_name: str, profile_name: str = None) -> Dict[str, Any]:
    """
    Main function wrapper for ebs_volume_kms_encryption_enabled.
    
    Args:
        region_name (str): AWS region name
        profile_name (str): AWS profile name (optional)
        
    Returns:
        Dict: Results summary
    """
    COMPLIANCE_DATA = load_rule_metadata("ebs_volume_kms_encryption_enabled")
    
    # TODO: Implement SecurityEngine integration when available
    # from data_security_engine import SecurityEngine
    # engine = SecurityEngine(COMPLIANCE_DATA)
    # return engine.run_check(region_name, profile_name, ebs_volume_kms_encryption_enabled_check)
    
    # Current implementation
    findings = ebs_volume_kms_encryption_enabled_check(region_name, profile_name)
    
    # Calculate compliance statistics
    total_findings = len(findings)
    compliant_findings = len([f for f in findings if f['status'] == 'COMPLIANT'])
    non_compliant_findings = len([f for f in findings if f['status'] == 'NON_COMPLIANT'])
    error_findings = len([f for f in findings if f['status'] == 'ERROR'])
    
    return {
        "function_name": "ebs_volume_kms_encryption_enabled",
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
    """CLI entry point for ebs_volume_kms_encryption_enabled."""
    # TODO: Implement setup_command_line_interface() when data_security_engine is available
    # from data_security_engine import setup_command_line_interface, save_results, exit_with_status
    # args = setup_command_line_interface()
    # results = ebs_volume_kms_encryption_enabled(args.region, args.profile)
    # save_results(results, args.output_file)
    # exit_with_status(results)
    
    # Current CLI implementation
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Ensure EBS volumes use KMS encryption instead of default encryption for enhanced key management and audit trails."
    )
    parser.add_argument("--region", default="us-east-1", help="AWS region")
    parser.add_argument("--profile", help="AWS profile name")
    parser.add_argument("--output", help="Output file for results (JSON format)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        results = ebs_volume_kms_encryption_enabled(args.region, args.profile)
        
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

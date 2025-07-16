#!/usr/bin/env python3
"""
data_security_aws - ec2_ebs_volume_region_compliance

Ensure EBS volumes are created only in approved regions to meet data residency and sovereignty requirements.
"""

# Rule Metadata from YAML:
# Function Name: ec2_ebs_volume_region_compliance
# Capability: DATA_RESIDENCY
# Service: EC2
# Subservice: REGION
# Description: Ensure EBS volumes are created only in approved regions to meet data residency and sovereignty requirements.
# Risk Level: HIGH
# Recommendation: Ensure EBS volumes comply with region restrictions
# API Function: client = boto3.client('ec2')
# User Function: ec2_ebs_volume_region_compliance()

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
        "function_name": "ec2_ebs_volume_region_compliance",
        "title": "Ensure EBS volumes comply with region restrictions",
        "description": "Ensure EBS volumes are created only in approved regions to meet data residency and sovereignty requirements.",
        "capability": "data_residency",
        "service": "ec2",
        "subservice": "region",
        "risk": "HIGH",
        "existing": False
    }

def ec2_ebs_volume_region_compliance_check(region_name: str, profile_name: str = None) -> List[Dict[str, Any]]:
    """
    Check ec2 resources for data_residency compliance.
    
    Args:
        region_name (str): AWS region name
        profile_name (str): AWS profile name (optional)
        
    Returns:
        List[Dict]: List of compliance findings
    """
    findings = []
    
    # Define approved regions for different compliance jurisdictions
    approved_regions = {
        'US': ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2'],
        'EU': ['eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-central-1', 'eu-north-1'],
        'APAC': ['ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1', 'ap-northeast-2', 'ap-south-1'],
        'CA': ['ca-central-1'],
        'UK': ['eu-west-2'],  # London
        'AU': ['ap-southeast-2'],  # Sydney
        'JP': ['ap-northeast-1']  # Tokyo
    }
    
    try:
        # Initialize boto3 client
        session = boto3.Session(profile_name=profile_name)
        ec2_client = session.client('ec2', region_name=region_name)
        
        logger.info(f"Checking ec2 resources for data_residency compliance in region {region_name}")
        
        # Determine the compliance jurisdiction for the current region
        current_jurisdiction = None
        for jurisdiction, regions in approved_regions.items():
            if region_name in regions:
                current_jurisdiction = jurisdiction
                break
        
        if not current_jurisdiction:
            # Region is not in any approved jurisdiction
            findings.append({
                "region": region_name,
                "profile": profile_name or "default",
                "resource_type": "ec2_region",
                "resource_id": f"region:{region_name}",
                "status": "NON_COMPLIANT",
                "risk_level": "HIGH",
                "recommendation": "EBS volumes should not be created in non-approved regions",
                "details": {
                    "current_region": region_name,
                    "violation": f"Region {region_name} is not in any approved jurisdiction",
                    "approved_regions": approved_regions
                }
            })
            return findings
        
        # Get all EBS volumes in the region
        paginator = ec2_client.get_paginator('describe_volumes')
        
        for page in paginator.paginate():
            for volume in page['Volumes']:
                volume_id = volume.get('VolumeId')
                
                try:
                    region_violations = []
                    compliance_details = {
                        'volume_id': volume_id,
                        'current_region': region_name,
                        'current_jurisdiction': current_jurisdiction,
                        'region_compliance_checks': []
                    }
                    
                    # Get volume tags to check for compliance requirements
                    tags = {tag.get('Key'): tag.get('Value') for tag in volume.get('Tags', [])}
                    
                    # Check if volume has data jurisdiction tags
                    data_jurisdiction = tags.get('DataJurisdiction', '').upper()
                    data_residency = tags.get('DataResidency', '').upper()
                    compliance_region = tags.get('ComplianceRegion', '').upper()
                    
                    # Validate jurisdiction compliance
                    if data_jurisdiction:
                        if data_jurisdiction != current_jurisdiction:
                            if data_jurisdiction in approved_regions:
                                if region_name not in approved_regions[data_jurisdiction]:
                                    region_violations.append({
                                        'violation_type': 'jurisdiction_mismatch',
                                        'message': f"Volume tagged for {data_jurisdiction} jurisdiction but stored in {current_jurisdiction} region",
                                        'expected_regions': approved_regions[data_jurisdiction],
                                        'current_region': region_name
                                    })
                            else:
                                region_violations.append({
                                    'violation_type': 'invalid_jurisdiction',
                                    'message': f"Invalid data jurisdiction tag: {data_jurisdiction}",
                                    'valid_jurisdictions': list(approved_regions.keys())
                                })
                        
                        compliance_details['region_compliance_checks'].append({
                            'check': 'data_jurisdiction_tag',
                            'tagged_jurisdiction': data_jurisdiction,
                            'compliant': len([v for v in region_violations if v['violation_type'] == 'jurisdiction_mismatch']) == 0
                        })
                    
                    # Check specific region requirements
                    if data_residency:
                        residency_region = data_residency.lower().replace('_', '-')
                        if residency_region != region_name:
                            region_violations.append({
                                'violation_type': 'residency_mismatch',
                                'message': f"Volume requires data residency in {data_residency} but stored in {region_name}",
                                'required_region': residency_region,
                                'current_region': region_name
                            })
                        
                        compliance_details['region_compliance_checks'].append({
                            'check': 'data_residency_tag',
                            'required_region': residency_region,
                            'compliant': residency_region == region_name
                        })
                    
                    # Check compliance region tag
                    if compliance_region:
                        if compliance_region != region_name.upper():
                            region_violations.append({
                                'violation_type': 'compliance_region_mismatch',
                                'message': f"Volume tagged for compliance in {compliance_region} but stored in {region_name.upper()}",
                                'required_region': compliance_region,
                                'current_region': region_name.upper()
                            })
                        
                        compliance_details['region_compliance_checks'].append({
                            'check': 'compliance_region_tag',
                            'required_region': compliance_region,
                            'compliant': compliance_region == region_name.upper()
                        })
                    
                    # Check availability zone compliance within region
                    availability_zone = volume.get('AvailabilityZone')
                    if availability_zone:
                        if not availability_zone.startswith(region_name):
                            region_violations.append({
                                'violation_type': 'az_region_mismatch',
                                'message': f"Volume availability zone {availability_zone} does not match region {region_name}",
                                'volume_az': availability_zone,
                                'expected_region': region_name
                            })
                        
                        # Check for specific AZ restrictions if tagged
                        required_az = tags.get('RequiredAvailabilityZone', '')
                        if required_az and required_az != availability_zone:
                            region_violations.append({
                                'violation_type': 'az_requirement_violation',
                                'message': f"Volume not in required availability zone: {required_az}",
                                'current_az': availability_zone,
                                'required_az': required_az
                            })
                    
                    # Check for cross-region snapshot sources
                    snapshot_id = volume.get('SnapshotId')
                    if snapshot_id:
                        try:
                            snapshots_response = ec2_client.describe_snapshots(SnapshotIds=[snapshot_id])
                            for snapshot in snapshots_response.get('Snapshots', []):
                                # Check if snapshot has region tags that differ from current region
                                snapshot_tags = {tag.get('Key'): tag.get('Value') for tag in snapshot.get('Tags', [])}
                                snapshot_region = snapshot_tags.get('SourceRegion', '').lower()
                                
                                if snapshot_region and snapshot_region != region_name:
                                    # Determine source jurisdiction
                                    source_jurisdiction = None
                                    for jurisdiction, regions in approved_regions.items():
                                        if snapshot_region in regions:
                                            source_jurisdiction = jurisdiction
                                            break
                                    
                                    if source_jurisdiction != current_jurisdiction:
                                        region_violations.append({
                                            'violation_type': 'cross_jurisdiction_snapshot',
                                            'message': f"Volume created from snapshot in different jurisdiction: {source_jurisdiction}",
                                            'snapshot_id': snapshot_id,
                                            'snapshot_region': snapshot_region,
                                            'source_jurisdiction': source_jurisdiction
                                        })
                        except Exception as snapshot_error:
                            logger.warning(f"Failed to check snapshot {snapshot_id}: {snapshot_error}")
                    
                    # Check encryption key region compliance
                    kms_key_id = volume.get('KmsKeyId')
                    if kms_key_id:
                        # Extract region from KMS key ARN if present
                        if kms_key_id.startswith('arn:aws:kms:'):
                            key_region = kms_key_id.split(':')[3]
                            if key_region != region_name:
                                region_violations.append({
                                    'violation_type': 'cross_region_kms_key',
                                    'message': f"Volume uses KMS key from different region: {key_region}",
                                    'key_region': key_region,
                                    'volume_region': region_name,
                                    'kms_key_id': kms_key_id
                                })
                    
                    # Check volume attachments for cross-region instances
                    attachments = volume.get('Attachments', [])
                    for attachment in attachments:
                        instance_id = attachment.get('InstanceId')
                        if instance_id:
                            try:
                                instances_response = ec2_client.describe_instances(InstanceIds=[instance_id])
                                for reservation in instances_response.get('Reservations', []):
                                    for instance in reservation.get('Instances', []):
                                        instance_az = instance.get('Placement', {}).get('AvailabilityZone')
                                        if instance_az and not instance_az.startswith(region_name):
                                            region_violations.append({
                                                'violation_type': 'cross_region_attachment',
                                                'message': f"Volume attached to instance in different region",
                                                'instance_id': instance_id,
                                                'instance_az': instance_az,
                                                'volume_region': region_name
                                            })
                            except Exception as instance_error:
                                logger.warning(f"Failed to check attached instance {instance_id}: {instance_error}")
                    
                    # Add volume details
                    compliance_details['volume_details'] = {
                        'volume_type': volume.get('VolumeType'),
                        'size': volume.get('Size'),
                        'state': volume.get('State'),
                        'availability_zone': availability_zone,
                        'create_time': volume.get('CreateTime').isoformat() if volume.get('CreateTime') else None,
                        'encrypted': volume.get('Encrypted', False),
                        'kms_key_id': kms_key_id,
                        'snapshot_id': snapshot_id,
                        'iops': volume.get('Iops'),
                        'throughput': volume.get('Throughput')
                    }
                    
                    compliance_details['volume_tags'] = tags
                    compliance_details['attachments'] = [{
                        'instance_id': att.get('InstanceId'),
                        'device': att.get('Device'),
                        'state': att.get('State')
                    } for att in attachments]
                    
                    # Determine compliance status
                    high_risk_violations = [v for v in region_violations if v.get('violation_type') in 
                                          ['jurisdiction_mismatch', 'cross_jurisdiction_snapshot', 'cross_region_kms_key']]
                    
                    if high_risk_violations or len(region_violations) > 0:
                        findings.append({
                            "region": region_name,
                            "profile": profile_name or "default",
                            "resource_type": "ec2_ebs_volume",
                            "resource_id": volume_id,
                            "status": "NON_COMPLIANT",
                            "risk_level": "HIGH",
                            "recommendation": "Ensure EBS volume complies with region restrictions",
                            "details": {
                                **compliance_details,
                                "violation": f"Volume has {len(region_violations)} region compliance violations",
                                "region_violations": region_violations,
                                "high_risk_violations": high_risk_violations
                            }
                        })
                    else:
                        findings.append({
                            "region": region_name,
                            "profile": profile_name or "default",
                            "resource_type": "ec2_ebs_volume",
                            "resource_id": volume_id,
                            "status": "COMPLIANT",
                            "risk_level": "HIGH",
                            "recommendation": "EBS volume complies with region restrictions",
                            "details": compliance_details
                        })
                        
                except Exception as volume_error:
                    logger.warning(f"Failed to check volume {volume_id}: {volume_error}")
                    findings.append({
                        "region": region_name,
                        "profile": profile_name or "default",
                        "resource_type": "ec2_ebs_volume",
                        "resource_id": volume_id,
                        "status": "ERROR",
                        "risk_level": "HIGH",
                        "recommendation": "Unable to check volume region compliance",
                        "details": {
                            "volume_id": volume_id,
                            "error": str(volume_error)
                        }
                    })
        
        logger.info(f"Completed checking ec2_ebs_volume_region_compliance. Found {len(findings)} findings.")
        
    except Exception as e:
        logger.error(f"Failed to check ec2_ebs_volume_region_compliance: {e}")
        findings.append({
            "region": region_name,
            "profile": profile_name or "default",
            "resource_type": "ec2_ebs_volume",
            "resource_id": "unknown",
            "status": "ERROR",
            "risk_level": "HIGH",
            "recommendation": "Fix API access issues",
            "details": {
                "error": str(e)
            }
        })
    
    return findings

def ec2_ebs_volume_region_compliance(region_name: str, profile_name: str = None) -> Dict[str, Any]:
    """
    Main function wrapper for ec2_ebs_volume_region_compliance.
    
    Args:
        region_name (str): AWS region name
        profile_name (str): AWS profile name (optional)
        
    Returns:
        Dict: Results summary
    """
    COMPLIANCE_DATA = load_rule_metadata("ec2_ebs_volume_region_compliance")
    
    # TODO: Implement SecurityEngine integration when available
    # from data_security_engine import SecurityEngine
    # engine = SecurityEngine(COMPLIANCE_DATA)
    # return engine.run_check(region_name, profile_name, ec2_ebs_volume_region_compliance_check)
    
    # Current implementation
    findings = ec2_ebs_volume_region_compliance_check(region_name, profile_name)
    
    # Calculate compliance statistics
    total_findings = len(findings)
    compliant_findings = len([f for f in findings if f['status'] == 'COMPLIANT'])
    non_compliant_findings = len([f for f in findings if f['status'] == 'NON_COMPLIANT'])
    error_findings = len([f for f in findings if f['status'] == 'ERROR'])
    
    return {
        "function_name": "ec2_ebs_volume_region_compliance",
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
    """CLI entry point for ec2_ebs_volume_region_compliance."""
    # TODO: Implement setup_command_line_interface() when data_security_engine is available
    # from data_security_engine import setup_command_line_interface, save_results, exit_with_status
    # args = setup_command_line_interface()
    # results = ec2_ebs_volume_region_compliance(args.region, args.profile)
    # save_results(results, args.output_file)
    # exit_with_status(results)
    
    # Current CLI implementation
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Ensure EBS volumes are created only in approved regions to meet data residency and sovereignty requirements."
    )
    parser.add_argument("--region", default="us-east-1", help="AWS region")
    parser.add_argument("--profile", help="AWS profile name")
    parser.add_argument("--output", help="Output file for results (JSON format)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        results = ec2_ebs_volume_region_compliance(args.region, args.profile)
        
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

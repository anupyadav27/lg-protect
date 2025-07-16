#!/usr/bin/env python3
"""
data_security_aws - ec2_instance_region_restriction_enforced

Ensure EC2 instances are launched only in approved regions to comply with data residency requirements.
"""

# Rule Metadata from YAML:
# Function Name: ec2_instance_region_restriction_enforced
# Capability: DATA_RESIDENCY
# Service: EC2
# Subservice: REGION
# Description: Ensure EC2 instances are launched only in approved regions to comply with data residency requirements.
# Risk Level: HIGH
# Recommendation: Enforce region restrictions for EC2 instances
# API Function: client = boto3.client('ec2')
# User Function: ec2_instance_region_restriction_enforced()

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
        "function_name": "ec2_instance_region_restriction_enforced",
        "title": "Enforce region restrictions for EC2 instances",
        "description": "Ensure EC2 instances are launched only in approved regions to comply with data residency requirements.",
        "capability": "data_residency",
        "service": "ec2",
        "subservice": "region",
        "risk": "HIGH",
        "existing": False
    }

def ec2_instance_region_restriction_enforced_check(region_name: str, profile_name: str = None) -> List[Dict[str, Any]]:
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
                "recommendation": "EC2 instances should not be launched in non-approved regions",
                "details": {
                    "current_region": region_name,
                    "violation": f"Region {region_name} is not in any approved jurisdiction",
                    "approved_regions": approved_regions
                }
            })
            return findings
        
        # Get all EC2 instances in the region
        paginator = ec2_client.get_paginator('describe_instances')
        
        for page in paginator.paginate():
            for reservation in page['Reservations']:
                for instance in reservation['Instances']:
                    instance_id = instance.get('InstanceId')
                    
                    try:
                        region_violations = []
                        compliance_details = {
                            'instance_id': instance_id,
                            'current_region': region_name,
                            'current_jurisdiction': current_jurisdiction,
                            'instance_state': instance.get('State', {}).get('Name'),
                            'region_compliance_checks': []
                        }
                        
                        # Get instance tags to check for compliance requirements
                        tags = {tag.get('Key'): tag.get('Value') for tag in instance.get('Tags', [])}
                        
                        # Check if instance has data jurisdiction tags
                        data_jurisdiction = tags.get('DataJurisdiction', '').upper()
                        data_residency = tags.get('DataResidency', '').upper()
                        compliance_region = tags.get('ComplianceRegion', '').upper()
                        
                        # Validate jurisdiction compliance
                        if data_jurisdiction:
                            if data_jurisdiction != current_jurisdiction:
                                # Check if the tagged jurisdiction allows this region
                                if data_jurisdiction in approved_regions:
                                    if region_name not in approved_regions[data_jurisdiction]:
                                        region_violations.append({
                                            'violation_type': 'jurisdiction_mismatch',
                                            'message': f"Instance tagged for {data_jurisdiction} jurisdiction but deployed in {current_jurisdiction} region",
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
                            # Extract region from data residency tag
                            residency_region = data_residency.lower().replace('_', '-')
                            if residency_region != region_name:
                                region_violations.append({
                                    'violation_type': 'residency_mismatch',
                                    'message': f"Instance requires data residency in {data_residency} but deployed in {region_name}",
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
                                    'message': f"Instance tagged for compliance in {compliance_region} but deployed in {region_name.upper()}",
                                    'required_region': compliance_region,
                                    'current_region': region_name.upper()
                                })
                            
                            compliance_details['region_compliance_checks'].append({
                                'check': 'compliance_region_tag',
                                'required_region': compliance_region,
                                'compliant': compliance_region == region_name.upper()
                            })
                        
                        # Check for cross-region dependencies
                        cross_region_dependencies = []
                        
                        # Check EBS volumes
                        for block_device in instance.get('BlockDeviceMappings', []):
                            ebs = block_device.get('Ebs', {})
                            volume_id = ebs.get('VolumeId')
                            if volume_id:
                                try:
                                    volumes_response = ec2_client.describe_volumes(VolumeIds=[volume_id])
                                    for volume in volumes_response.get('Volumes', []):
                                        volume_az = volume.get('AvailabilityZone')
                                        if volume_az and not volume_az.startswith(region_name):
                                            cross_region_dependencies.append({
                                                'type': 'ebs_volume',
                                                'resource_id': volume_id,
                                                'availability_zone': volume_az,
                                                'compliant': False
                                            })
                                except Exception as vol_error:
                                    logger.warning(f"Failed to check volume {volume_id}: {vol_error}")
                        
                        # Check security groups
                        for sg in instance.get('SecurityGroups', []):
                            sg_id = sg.get('GroupId')
                            try:
                                sg_response = ec2_client.describe_security_groups(GroupIds=[sg_id])
                                for security_group in sg_response.get('SecurityGroups', []):
                                    vpc_id = security_group.get('VpcId')
                                    if vpc_id:
                                        # Check if VPC is in the same region (VPCs are region-specific)
                                        cross_region_dependencies.append({
                                            'type': 'security_group',
                                            'resource_id': sg_id,
                                            'vpc_id': vpc_id,
                                            'compliant': True  # SGs are always in same region as instance
                                        })
                            except Exception as sg_error:
                                logger.warning(f"Failed to check security group {sg_id}: {sg_error}")
                        
                        # Check instance image (AMI) region
                        image_id = instance.get('ImageId')
                        if image_id:
                            try:
                                images_response = ec2_client.describe_images(ImageIds=[image_id])
                                for image in images_response.get('Images', []):
                                    image_location = image.get('ImageLocation', '')
                                    # AMIs are region-specific, but check for any indicators of cross-region copying
                                    cross_region_dependencies.append({
                                        'type': 'ami',
                                        'resource_id': image_id,
                                        'image_location': image_location,
                                        'compliant': True  # AMIs used in region are typically compliant
                                    })
                            except Exception as ami_error:
                                logger.warning(f"Failed to check AMI {image_id}: {ami_error}")
                        
                        # Add cross-region dependency violations
                        for dependency in cross_region_dependencies:
                            if not dependency.get('compliant', True):
                                region_violations.append({
                                    'violation_type': 'cross_region_dependency',
                                    'message': f"Instance has {dependency['type']} dependency in different region",
                                    'dependency': dependency
                                })
                        
                        compliance_details['cross_region_dependencies'] = cross_region_dependencies
                        compliance_details['tags'] = {
                            'data_jurisdiction': data_jurisdiction,
                            'data_residency': data_residency,
                            'compliance_region': compliance_region
                        }
                        compliance_details['instance_details'] = {
                            'instance_type': instance.get('InstanceType'),
                            'platform': instance.get('Platform'),
                            'vpc_id': instance.get('VpcId'),
                            'subnet_id': instance.get('SubnetId'),
                            'availability_zone': instance.get('Placement', {}).get('AvailabilityZone'),
                            'launch_time': instance.get('LaunchTime').isoformat() if instance.get('LaunchTime') else None
                        }
                        
                        # Determine compliance status
                        if region_violations:
                            findings.append({
                                "region": region_name,
                                "profile": profile_name or "default",
                                "resource_type": "ec2_instance",
                                "resource_id": instance_id,
                                "status": "NON_COMPLIANT",
                                "risk_level": "HIGH",
                                "recommendation": "Ensure EC2 instance complies with region restrictions",
                                "details": {
                                    **compliance_details,
                                    "violation": f"Instance has {len(region_violations)} region compliance violations",
                                    "region_violations": region_violations
                                }
                            })
                        else:
                            findings.append({
                                "region": region_name,
                                "profile": profile_name or "default",
                                "resource_type": "ec2_instance",
                                "resource_id": instance_id,
                                "status": "COMPLIANT",
                                "risk_level": "HIGH",
                                "recommendation": "EC2 instance complies with region restrictions",
                                "details": compliance_details
                            })
                            
                    except Exception as instance_error:
                        logger.warning(f"Failed to check instance {instance_id}: {instance_error}")
                        findings.append({
                            "region": region_name,
                            "profile": profile_name or "default",
                            "resource_type": "ec2_instance",
                            "resource_id": instance_id,
                            "status": "ERROR",
                            "risk_level": "HIGH",
                            "recommendation": "Unable to check region restriction compliance",
                            "details": {
                                "instance_id": instance_id,
                                "error": str(instance_error)
                            }
                        })
        
        logger.info(f"Completed checking ec2_instance_region_restriction_enforced. Found {len(findings)} findings.")
        
    except Exception as e:
        logger.error(f"Failed to check ec2_instance_region_restriction_enforced: {e}")
        findings.append({
            "region": region_name,
            "profile": profile_name or "default",
            "resource_type": "ec2_instance",
            "resource_id": "unknown",
            "status": "ERROR",
            "risk_level": "HIGH",
            "recommendation": "Fix API access issues",
            "details": {
                "error": str(e)
            }
        })
    
    return findings

def ec2_instance_region_restriction_enforced(region_name: str, profile_name: str = None) -> Dict[str, Any]:
    """
    Main function wrapper for ec2_instance_region_restriction_enforced.
    
    Args:
        region_name (str): AWS region name
        profile_name (str): AWS profile name (optional)
        
    Returns:
        Dict: Results summary
    """
    COMPLIANCE_DATA = load_rule_metadata("ec2_instance_region_restriction_enforced")
    
    # TODO: Implement SecurityEngine integration when available
    # from data_security_engine import SecurityEngine
    # engine = SecurityEngine(COMPLIANCE_DATA)
    # return engine.run_check(region_name, profile_name, ec2_instance_region_restriction_enforced_check)
    
    # Current implementation
    findings = ec2_instance_region_restriction_enforced_check(region_name, profile_name)
    
    # Calculate compliance statistics
    total_findings = len(findings)
    compliant_findings = len([f for f in findings if f['status'] == 'COMPLIANT'])
    non_compliant_findings = len([f for f in findings if f['status'] == 'NON_COMPLIANT'])
    error_findings = len([f for f in findings if f['status'] == 'ERROR'])
    
    return {
        "function_name": "ec2_instance_region_restriction_enforced",
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
    """CLI entry point for ec2_instance_region_restriction_enforced."""
    # TODO: Implement setup_command_line_interface() when data_security_engine is available
    # from data_security_engine import setup_command_line_interface, save_results, exit_with_status
    # args = setup_command_line_interface()
    # results = ec2_instance_region_restriction_enforced(args.region, args.profile)
    # save_results(results, args.output_file)
    # exit_with_status(results)
    
    # Current CLI implementation
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Ensure EC2 instances are launched only in approved regions to comply with data residency requirements."
    )
    parser.add_argument("--region", default="us-east-1", help="AWS region")
    parser.add_argument("--profile", help="AWS profile name")
    parser.add_argument("--output", help="Output file for results (JSON format)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        results = ec2_instance_region_restriction_enforced(args.region, args.profile)
        
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

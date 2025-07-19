#!/usr/bin/env python3
"""
data_security_aws - ec2_placement_group_region_compliance

Ensure EC2 placement groups are created only in approved regions to maintain data residency compliance.
"""

# Rule Metadata from YAML:
# Function Name: ec2_placement_group_region_compliance
# Capability: DATA_RESIDENCY
# Service: EC2
# Subservice: REGION
# Description: Ensure EC2 placement groups are created only in approved regions to maintain data residency compliance.
# Risk Level: MEDIUM
# Recommendation: Ensure placement groups comply with region restrictions
# API Function: client = boto3.client('ec2')
# User Function: ec2_placement_group_region_compliance()

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
        "function_name": "ec2_placement_group_region_compliance",
        "title": "Ensure placement groups comply with region restrictions",
        "description": "Ensure EC2 placement groups are created only in approved regions to maintain data residency compliance.",
        "capability": "data_residency",
        "service": "ec2",
        "subservice": "region",
        "risk": "MEDIUM",
        "existing": False
    }

def ec2_placement_group_region_compliance_check(region_name: str, profile_name: str = None) -> List[Dict[str, Any]]:
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
        
        logger.info(f"Checking ec2 placement groups for data_residency compliance in region {region_name}")
        
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
                "risk_level": "MEDIUM",
                "recommendation": "Placement groups should not be created in non-approved regions",
                "details": {
                    "current_region": region_name,
                    "violation": f"Region {region_name} is not in any approved jurisdiction",
                    "approved_regions": approved_regions
                }
            })
            return findings
        
        # Get all placement groups in the region
        try:
            response = ec2_client.describe_placement_groups()
            placement_groups = response.get('PlacementGroups', [])
        except Exception as api_error:
            logger.error(f"Failed to describe placement groups: {api_error}")
            findings.append({
                "region": region_name,
                "profile": profile_name or "default",
                "resource_type": "ec2_placement_group",
                "resource_id": "unknown",
                "status": "ERROR",
                "risk_level": "MEDIUM",
                "recommendation": "Fix API access issues for placement groups",
                "details": {
                    "error": str(api_error)
                }
            })
            return findings
        
        for placement_group in placement_groups:
            group_name = placement_group.get('GroupName')
            group_id = placement_group.get('GroupId', group_name)
            
            try:
                region_violations = []
                compliance_details = {
                    'group_name': group_name,
                    'group_id': group_id,
                    'current_region': region_name,
                    'current_jurisdiction': current_jurisdiction,
                    'region_compliance_checks': []
                }
                
                # Get placement group tags to check for compliance requirements
                tags = {}
                try:
                    if group_id:
                        tags_response = ec2_client.describe_tags(
                            Filters=[
                                {'Name': 'resource-id', 'Values': [group_id]},
                                {'Name': 'resource-type', 'Values': ['placement-group']}
                            ]
                        )
                        tags = {tag.get('Key'): tag.get('Value') for tag in tags_response.get('Tags', [])}
                except Exception as tags_error:
                    logger.warning(f"Failed to get tags for placement group {group_id}: {tags_error}")
                
                # Check if placement group has data jurisdiction tags
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
                                    'message': f"Placement group tagged for {data_jurisdiction} jurisdiction but located in {current_jurisdiction} region",
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
                            'message': f"Placement group requires data residency in {data_residency} but located in {region_name}",
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
                            'message': f"Placement group tagged for compliance in {compliance_region} but located in {region_name.upper()}",
                            'required_region': compliance_region,
                            'current_region': region_name.upper()
                        })
                    
                    compliance_details['region_compliance_checks'].append({
                        'check': 'compliance_region_tag',
                        'required_region': compliance_region,
                        'compliant': compliance_region == region_name.upper()
                    })
                
                # Check placement group strategy and availability zone compliance
                strategy = placement_group.get('Strategy')
                state = placement_group.get('State')
                
                # For cluster strategy, check if instances are in same AZ (important for data locality)
                if strategy == 'cluster':
                    # Get instances in this placement group
                    try:
                        instances_response = ec2_client.describe_instances(
                            Filters=[
                                {'Name': 'placement-group-name', 'Values': [group_name]}
                            ]
                        )
                        
                        instance_azs = set()
                        instance_count = 0
                        
                        for reservation in instances_response.get('Reservations', []):
                            for instance in reservation.get('Instances', []):
                                instance_count += 1
                                instance_az = instance.get('Placement', {}).get('AvailabilityZone')
                                if instance_az:
                                    instance_azs.add(instance_az)
                                    
                                    # Validate AZ is in current region
                                    if not instance_az.startswith(region_name):
                                        region_violations.append({
                                            'violation_type': 'instance_cross_region',
                                            'message': f"Instance in placement group is in different region AZ: {instance_az}",
                                            'instance_id': instance.get('InstanceId'),
                                            'instance_az': instance_az,
                                            'expected_region': region_name
                                        })
                        
                        # For cluster strategy, instances should be in same AZ for optimal performance
                        if len(instance_azs) > 1:
                            region_violations.append({
                                'violation_type': 'cluster_multi_az',
                                'message': f"Cluster placement group has instances across multiple AZs: {list(instance_azs)}",
                                'instance_azs': list(instance_azs),
                                'strategy': strategy
                            })
                        
                        compliance_details['instance_details'] = {
                            'instance_count': instance_count,
                            'availability_zones': list(instance_azs),
                            'cross_az_instances': len(instance_azs) > 1 if strategy == 'cluster' else False
                        }
                        
                    except Exception as instances_error:
                        logger.warning(f"Failed to check instances in placement group {group_name}: {instances_error}")
                
                # Check for required AZ restrictions if tagged
                required_az = tags.get('RequiredAvailabilityZone', '')
                if required_az and required_az.startswith(region_name):
                    # Validate instances are in required AZ
                    try:
                        instances_response = ec2_client.describe_instances(
                            Filters=[
                                {'Name': 'placement-group-name', 'Values': [group_name]}
                            ]
                        )
                        
                        for reservation in instances_response.get('Reservations', []):
                            for instance in reservation.get('Instances', []):
                                instance_az = instance.get('Placement', {}).get('AvailabilityZone')
                                if instance_az and instance_az != required_az:
                                    region_violations.append({
                                        'violation_type': 'az_requirement_violation',
                                        'message': f"Instance not in required availability zone: {required_az}",
                                        'instance_id': instance.get('InstanceId'),
                                        'current_az': instance_az,
                                        'required_az': required_az
                                    })
                    except Exception as az_check_error:
                        logger.warning(f"Failed to check AZ requirements for placement group {group_name}: {az_check_error}")
                
                # Add placement group details
                compliance_details['placement_group_details'] = {
                    'group_name': group_name,
                    'group_id': group_id,
                    'strategy': strategy,
                    'state': state,
                    'partition_count': placement_group.get('PartitionCount'),
                    'spread_level': placement_group.get('SpreadLevel'),
                    'tags': tags
                }
                
                # Check for cross-region network interfaces or resources
                # Placement groups should only contain resources in the same region
                if state == 'available':
                    try:
                        # Check network interfaces associated with placement group instances
                        instances_response = ec2_client.describe_instances(
                            Filters=[
                                {'Name': 'placement-group-name', 'Values': [group_name]}
                            ]
                        )
                        
                        for reservation in instances_response.get('Reservations', []):
                            for instance in reservation.get('Instances', []):
                                for eni in instance.get('NetworkInterfaces', []):
                                    subnet_id = eni.get('SubnetId')
                                    if subnet_id:
                                        # Check if subnet is in current region (indirect check via AZ)
                                        eni_az = eni.get('AvailabilityZone')
                                        if eni_az and not eni_az.startswith(region_name):
                                            region_violations.append({
                                                'violation_type': 'cross_region_network_interface',
                                                'message': f"Instance network interface in different region: {eni_az}",
                                                'instance_id': instance.get('InstanceId'),
                                                'eni_id': eni.get('NetworkInterfaceId'),
                                                'eni_az': eni_az,
                                                'expected_region': region_name
                                            })
                    except Exception as network_error:
                        logger.warning(f"Failed to check network interfaces for placement group {group_name}: {network_error}")
                
                # Determine compliance status
                high_risk_violations = [v for v in region_violations if v.get('violation_type') in 
                                      ['jurisdiction_mismatch', 'instance_cross_region', 'cross_region_network_interface']]
                
                if high_risk_violations or len(region_violations) > 0:
                    findings.append({
                        "region": region_name,
                        "profile": profile_name or "default",
                        "resource_type": "ec2_placement_group",
                        "resource_id": group_id or group_name,
                        "status": "NON_COMPLIANT",
                        "risk_level": "MEDIUM",
                        "recommendation": "Ensure placement group complies with region restrictions",
                        "details": {
                            **compliance_details,
                            "violation": f"Placement group has {len(region_violations)} region compliance violations",
                            "region_violations": region_violations,
                            "high_risk_violations": high_risk_violations
                        }
                    })
                else:
                    findings.append({
                        "region": region_name,
                        "profile": profile_name or "default",
                        "resource_type": "ec2_placement_group",
                        "resource_id": group_id or group_name,
                        "status": "COMPLIANT",
                        "risk_level": "MEDIUM",
                        "recommendation": "Placement group complies with region restrictions",
                        "details": compliance_details
                    })
                    
            except Exception as group_error:
                logger.warning(f"Failed to check placement group {group_name}: {group_error}")
                findings.append({
                    "region": region_name,
                    "profile": profile_name or "default",
                    "resource_type": "ec2_placement_group",
                    "resource_id": group_id or group_name,
                    "status": "ERROR",
                    "risk_level": "MEDIUM",
                    "recommendation": "Unable to check placement group region compliance",
                    "details": {
                        "group_name": group_name,
                        "error": str(group_error)
                    }
                })
        
        logger.info(f"Completed checking ec2_placement_group_region_compliance. Found {len(findings)} findings.")
        
    except Exception as e:
        logger.error(f"Failed to check ec2_placement_group_region_compliance: {e}")
        findings.append({
            "region": region_name,
            "profile": profile_name or "default",
            "resource_type": "ec2_placement_group",
            "resource_id": "unknown",
            "status": "ERROR",
            "risk_level": "MEDIUM",
            "recommendation": "Fix API access issues",
            "details": {
                "error": str(e)
            }
        })
    
    return findings

def ec2_placement_group_region_compliance(region_name: str, profile_name: str = None) -> Dict[str, Any]:
    """
    Main function wrapper for ec2_placement_group_region_compliance.
    
    Args:
        region_name (str): AWS region name
        profile_name (str): AWS profile name (optional)
        
    Returns:
        Dict: Results summary
    """
    COMPLIANCE_DATA = load_rule_metadata("ec2_placement_group_region_compliance")
    
    # TODO: Implement SecurityEngine integration when available
    # from data_security_engine import SecurityEngine
    # engine = SecurityEngine(COMPLIANCE_DATA)
    # return engine.run_check(region_name, profile_name, ec2_placement_group_region_compliance_check)
    
    # Current implementation
    findings = ec2_placement_group_region_compliance_check(region_name, profile_name)
    
    # Calculate compliance statistics
    total_findings = len(findings)
    compliant_findings = len([f for f in findings if f['status'] == 'COMPLIANT'])
    non_compliant_findings = len([f for f in findings if f['status'] == 'NON_COMPLIANT'])
    error_findings = len([f for f in findings if f['status'] == 'ERROR'])
    
    return {
        "function_name": "ec2_placement_group_region_compliance",
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
    """CLI entry point for ec2_placement_group_region_compliance."""
    # TODO: Implement setup_command_line_interface() when data_security_engine is available
    # from data_security_engine import setup_command_line_interface, save_results, exit_with_status
    # args = setup_command_line_interface()
    # results = ec2_placement_group_region_compliance(args.region, args.profile)
    # save_results(results, args.output_file)
    # exit_with_status(results)
    
    # Current CLI implementation
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Ensure EC2 placement groups are created only in approved regions to maintain data residency compliance."
    )
    parser.add_argument("--region", default="us-east-1", help="AWS region")
    parser.add_argument("--profile", help="AWS profile name")
    parser.add_argument("--output", help="Output file for results (JSON format)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        results = ec2_placement_group_region_compliance(args.region, args.profile)
        
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

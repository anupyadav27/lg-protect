#!/usr/bin/env python3
"""
data_security_aws - ec2_ami_region_restriction_enforced

Ensure AMIs are shared and used only in approved regions to maintain data residency compliance.
"""

# Rule Metadata from YAML:
# Function Name: ec2_ami_region_restriction_enforced
# Capability: DATA_RESIDENCY
# Service: EC2
# Subservice: REGION
# Description: Ensure AMIs are shared and used only in approved regions to maintain data residency compliance.
# Risk Level: MEDIUM
# Recommendation: Restrict AMI usage to approved regions
# API Function: client = boto3.client('ec2')
# User Function: ec2_ami_region_restriction_enforced()

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
        "function_name": "ec2_ami_region_restriction_enforced",
        "title": "Restrict AMI usage to approved regions",
        "description": "Ensure AMIs are shared and used only in approved regions to maintain data residency compliance.",
        "capability": "data_residency",
        "service": "ec2",
        "subservice": "region",
        "risk": "MEDIUM",
        "existing": False
    }

def ec2_ami_region_restriction_enforced_check(region_name: str, profile_name: str = None) -> List[Dict[str, Any]]:
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
                "risk_level": "MEDIUM",
                "recommendation": "AMIs should not be stored or shared in non-approved regions",
                "details": {
                    "current_region": region_name,
                    "violation": f"Region {region_name} is not in any approved jurisdiction",
                    "approved_regions": approved_regions
                }
            })
            return findings
        
        # Get all AMIs owned by the account in the region
        try:
            # Check AMIs owned by the current account
            owned_images_response = ec2_client.describe_images(Owners=['self'])
            owned_images = owned_images_response.get('Images', [])
            
            for image in owned_images:
                image_id = image.get('ImageId')
                image_name = image.get('Name', '')
                
                try:
                    region_violations = []
                    compliance_details = {
                        'image_id': image_id,
                        'image_name': image_name,
                        'current_region': region_name,
                        'current_jurisdiction': current_jurisdiction,
                        'region_compliance_checks': []
                    }
                    
                    # Get image tags to check for compliance requirements
                    tags = {tag.get('Key'): tag.get('Value') for tag in image.get('Tags', [])}
                    
                    # Check if AMI has data jurisdiction tags
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
                                        'message': f"AMI tagged for {data_jurisdiction} jurisdiction but stored in {current_jurisdiction} region",
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
                                'message': f"AMI requires data residency in {data_residency} but stored in {region_name}",
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
                                'message': f"AMI tagged for compliance in {compliance_region} but stored in {region_name.upper()}",
                                'required_region': compliance_region,
                                'current_region': region_name.upper()
                            })
                        
                        compliance_details['region_compliance_checks'].append({
                            'check': 'compliance_region_tag',
                            'required_region': compliance_region,
                            'compliant': compliance_region == region_name.upper()
                        })
                    
                    # Check AMI launch permissions for cross-region sharing
                    try:
                        launch_perms_response = ec2_client.describe_image_attribute(
                            ImageId=image_id,
                            Attribute='launchPermission'
                        )
                        
                        launch_permissions = launch_perms_response.get('LaunchPermissions', [])
                        sharing_violations = []
                        
                        for permission in launch_permissions:
                            # Check for public sharing
                            if permission.get('Group') == 'all':
                                sharing_violations.append({
                                    'type': 'public_sharing',
                                    'message': 'AMI is publicly shared',
                                    'severity': 'HIGH'
                                })
                            
                            # Check for cross-account sharing
                            user_id = permission.get('UserId')
                            if user_id:
                                # Could implement additional checks for approved accounts
                                sharing_violations.append({
                                    'type': 'cross_account_sharing',
                                    'message': f'AMI shared with account: {user_id}',
                                    'account_id': user_id,
                                    'severity': 'MEDIUM'
                                })
                        
                        if sharing_violations:
                            region_violations.extend([{
                                'violation_type': 'sharing_violation',
                                'message': violation['message'],
                                'sharing_details': violation
                            } for violation in sharing_violations])
                        
                        compliance_details['sharing_analysis'] = {
                            'total_permissions': len(launch_permissions),
                            'sharing_violations': sharing_violations,
                            'is_public': any(p.get('Group') == 'all' for p in launch_permissions)
                        }
                        
                    except Exception as perms_error:
                        logger.warning(f"Failed to check launch permissions for AMI {image_id}: {perms_error}")
                        compliance_details['sharing_analysis'] = {'error': str(perms_error)}
                    
                    # Check snapshot dependencies
                    block_device_mappings = image.get('BlockDeviceMappings', [])
                    snapshot_violations = []
                    
                    for mapping in block_device_mappings:
                        ebs = mapping.get('Ebs', {})
                        snapshot_id = ebs.get('SnapshotId')
                        
                        if snapshot_id:
                            try:
                                snapshots_response = ec2_client.describe_snapshots(SnapshotIds=[snapshot_id])
                                for snapshot in snapshots_response.get('Snapshots', []):
                                    # Check snapshot tags for compliance
                                    snapshot_tags = {tag.get('Key'): tag.get('Value') for tag in snapshot.get('Tags', [])}
                                    snapshot_jurisdiction = snapshot_tags.get('DataJurisdiction', '').upper()
                                    
                                    if snapshot_jurisdiction and snapshot_jurisdiction != current_jurisdiction:
                                        snapshot_violations.append({
                                            'snapshot_id': snapshot_id,
                                            'violation': f'Snapshot jurisdiction {snapshot_jurisdiction} differs from current region jurisdiction {current_jurisdiction}'
                                        })
                            except Exception as snap_error:
                                logger.warning(f"Failed to check snapshot {snapshot_id}: {snap_error}")
                    
                    if snapshot_violations:
                        region_violations.extend([{
                            'violation_type': 'snapshot_jurisdiction_mismatch',
                            'message': violation['violation'],
                            'snapshot_id': violation['snapshot_id']
                        } for violation in snapshot_violations])
                    
                    # Add general AMI details
                    compliance_details['ami_details'] = {
                        'architecture': image.get('Architecture'),
                        'virtualization_type': image.get('VirtualizationType'),
                        'hypervisor': image.get('Hypervisor'),
                        'state': image.get('State'),
                        'creation_date': image.get('CreationDate'),
                        'owner_id': image.get('OwnerId'),
                        'public': image.get('Public', False)
                    }
                    
                    compliance_details['tags'] = {
                        'data_jurisdiction': data_jurisdiction,
                        'data_residency': data_residency,
                        'compliance_region': compliance_region
                    }
                    
                    # Determine compliance status
                    if region_violations:
                        findings.append({
                            "region": region_name,
                            "profile": profile_name or "default",
                            "resource_type": "ec2_ami",
                            "resource_id": image_id,
                            "status": "NON_COMPLIANT",
                            "risk_level": "MEDIUM",
                            "recommendation": "Ensure AMI complies with region restrictions and sharing policies",
                            "details": {
                                **compliance_details,
                                "violation": f"AMI has {len(region_violations)} region compliance violations",
                                "region_violations": region_violations
                            }
                        })
                    else:
                        findings.append({
                            "region": region_name,
                            "profile": profile_name or "default",
                            "resource_type": "ec2_ami",
                            "resource_id": image_id,
                            "status": "COMPLIANT",
                            "risk_level": "MEDIUM",
                            "recommendation": "AMI complies with region restrictions",
                            "details": compliance_details
                        })
                        
                except Exception as ami_error:
                    logger.warning(f"Failed to check AMI {image_id}: {ami_error}")
                    findings.append({
                        "region": region_name,
                        "profile": profile_name or "default",
                        "resource_type": "ec2_ami",
                        "resource_id": image_id,
                        "status": "ERROR",
                        "risk_level": "MEDIUM",
                        "recommendation": "Unable to check AMI region restriction compliance",
                        "details": {
                            "image_id": image_id,
                            "image_name": image_name,
                            "error": str(ami_error)
                        }
                    })
                    
        except Exception as images_error:
            logger.warning(f"Failed to list AMIs in region {region_name}: {images_error}")
            findings.append({
                "region": region_name,
                "profile": profile_name or "default",
                "resource_type": "ec2_ami",
                "resource_id": f"region:{region_name}",
                "status": "ERROR",
                "risk_level": "MEDIUM",
                "recommendation": "Unable to list AMIs in region",
                "details": {
                    "error": str(images_error)
                }
            })
        
        logger.info(f"Completed checking ec2_ami_region_restriction_enforced. Found {len(findings)} findings.")
        
    except Exception as e:
        logger.error(f"Failed to check ec2_ami_region_restriction_enforced: {e}")
        findings.append({
            "region": region_name,
            "profile": profile_name or "default",
            "resource_type": "ec2_ami",
            "resource_id": "unknown",
            "status": "ERROR",
            "risk_level": "MEDIUM",
            "recommendation": "Fix API access issues",
            "details": {
                "error": str(e)
            }
        })
    
    return findings

def ec2_ami_region_restriction_enforced(region_name: str, profile_name: str = None) -> Dict[str, Any]:
    """
    Main function wrapper for ec2_ami_region_restriction_enforced.
    
    Args:
        region_name (str): AWS region name
        profile_name (str): AWS profile name (optional)
        
    Returns:
        Dict: Results summary
    """
    COMPLIANCE_DATA = load_rule_metadata("ec2_ami_region_restriction_enforced")
    
    # TODO: Implement SecurityEngine integration when available
    # from data_security_engine import SecurityEngine
    # engine = SecurityEngine(COMPLIANCE_DATA)
    # return engine.run_check(region_name, profile_name, ec2_ami_region_restriction_enforced_check)
    
    # Current implementation
    findings = ec2_ami_region_restriction_enforced_check(region_name, profile_name)
    
    # Calculate compliance statistics
    total_findings = len(findings)
    compliant_findings = len([f for f in findings if f['status'] == 'COMPLIANT'])
    non_compliant_findings = len([f for f in findings if f['status'] == 'NON_COMPLIANT'])
    error_findings = len([f for f in findings if f['status'] == 'ERROR'])
    
    return {
        "function_name": "ec2_ami_region_restriction_enforced",
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
    """CLI entry point for ec2_ami_region_restriction_enforced."""
    # TODO: Implement setup_command_line_interface() when data_security_engine is available
    # from data_security_engine import setup_command_line_interface, save_results, exit_with_status
    # args = setup_command_line_interface()
    # results = ec2_ami_region_restriction_enforced(args.region, args.profile)
    # save_results(results, args.output_file)
    # exit_with_status(results)
    
    # Current CLI implementation
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Ensure AMIs are shared and used only in approved regions to maintain data residency compliance."
    )
    parser.add_argument("--region", default="us-east-1", help="AWS region")
    parser.add_argument("--profile", help="AWS profile name")
    parser.add_argument("--output", help="Output file for results (JSON format)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        results = ec2_ami_region_restriction_enforced(args.region, args.profile)
        
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

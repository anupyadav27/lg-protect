#!/usr/bin/env python3
"""
data_security_aws - ec2_snapshot_cross_region_copy_restricted

Ensure EBS snapshots are copied only to approved regions that meet data residency requirements.
"""

# Rule Metadata from YAML:
# Function Name: ec2_snapshot_cross_region_copy_restricted
# Capability: DATA_RESIDENCY
# Service: EC2
# Subservice: BACKUP
# Description: Ensure EBS snapshots are copied only to approved regions that meet data residency requirements.
# Risk Level: HIGH
# Recommendation: Restrict cross-region snapshot copying
# API Function: client = boto3.client('ec2')
# User Function: ec2_snapshot_cross_region_copy_restricted()

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
        "function_name": "ec2_snapshot_cross_region_copy_restricted",
        "title": "Restrict cross-region snapshot copying",
        "description": "Ensure EBS snapshots are copied only to approved regions that meet data residency requirements.",
        "capability": "data_residency",
        "service": "ec2",
        "subservice": "backup",
        "risk": "HIGH",
        "existing": False
    }

def ec2_snapshot_cross_region_copy_restricted_check(region_name: str, profile_name: str = None) -> List[Dict[str, Any]]:
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
                "recommendation": "EBS snapshots should not be created or copied in non-approved regions",
                "details": {
                    "current_region": region_name,
                    "violation": f"Region {region_name} is not in any approved jurisdiction",
                    "approved_regions": approved_regions
                }
            })
            return findings
        
        # Get all EBS snapshots owned by the account in the region
        paginator = ec2_client.get_paginator('describe_snapshots')
        
        for page in paginator.paginate(OwnerIds=['self']):
            for snapshot in page['Snapshots']:
                snapshot_id = snapshot.get('SnapshotId')
                
                try:
                    region_violations = []
                    compliance_details = {
                        'snapshot_id': snapshot_id,
                        'current_region': region_name,
                        'current_jurisdiction': current_jurisdiction,
                        'region_compliance_checks': []
                    }
                    
                    # Get snapshot tags to check for compliance requirements
                    tags = {tag.get('Key'): tag.get('Value') for tag in snapshot.get('Tags', [])}
                    
                    # Check if snapshot has data jurisdiction tags
                    data_jurisdiction = tags.get('DataJurisdiction', '').upper()
                    data_residency = tags.get('DataResidency', '').upper()
                    compliance_region = tags.get('ComplianceRegion', '').upper()
                    source_region = tags.get('SourceRegion', '').lower()
                    copy_source = tags.get('CopySource', '')
                    
                    # Validate jurisdiction compliance
                    if data_jurisdiction:
                        if data_jurisdiction != current_jurisdiction:
                            if data_jurisdiction in approved_regions:
                                if region_name not in approved_regions[data_jurisdiction]:
                                    region_violations.append({
                                        'violation_type': 'jurisdiction_mismatch',
                                        'message': f"Snapshot tagged for {data_jurisdiction} jurisdiction but stored in {current_jurisdiction} region",
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
                                'message': f"Snapshot requires data residency in {data_residency} but stored in {region_name}",
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
                                'message': f"Snapshot tagged for compliance in {compliance_region} but stored in {region_name.upper()}",
                                'required_region': compliance_region,
                                'current_region': region_name.upper()
                            })
                        
                        compliance_details['region_compliance_checks'].append({
                            'check': 'compliance_region_tag',
                            'required_region': compliance_region,
                            'compliant': compliance_region == region_name.upper()
                        })
                    
                    # Check if this is a copied snapshot and analyze cross-region copy compliance
                    snapshot_description = snapshot.get('Description', '')
                    is_copied_snapshot = False
                    source_region_detected = None
                    
                    # Detect copied snapshots by description pattern
                    if 'copy' in snapshot_description.lower() or 'copied from' in snapshot_description.lower():
                        is_copied_snapshot = True
                        # Try to extract source region from description
                        import re
                        region_pattern = r'([a-z]{2}-[a-z]+-\d+)'
                        matches = re.findall(region_pattern, snapshot_description.lower())
                        if matches:
                            for match in matches:
                                if match != region_name:
                                    source_region_detected = match
                                    break
                    
                    # Check source region tag
                    if source_region:
                        is_copied_snapshot = True
                        source_region_detected = source_region
                    
                    # Check copy source tag
                    if copy_source:
                        is_copied_snapshot = True
                        if ':' in copy_source:
                            # Extract region from ARN-like format
                            parts = copy_source.split(':')
                            if len(parts) >= 4:
                                source_region_detected = parts[3]
                    
                    if is_copied_snapshot:
                        compliance_details['is_copied_snapshot'] = True
                        compliance_details['source_region'] = source_region_detected
                        
                        if source_region_detected:
                            # Determine source region jurisdiction
                            source_jurisdiction = None
                            for jurisdiction, regions in approved_regions.items():
                                if source_region_detected in regions:
                                    source_jurisdiction = jurisdiction
                                    break
                            
                            if not source_jurisdiction:
                                region_violations.append({
                                    'violation_type': 'copy_from_unapproved_region',
                                    'message': f"Snapshot copied from unapproved region: {source_region_detected}",
                                    'source_region': source_region_detected
                                })
                            elif source_jurisdiction != current_jurisdiction:
                                region_violations.append({
                                    'violation_type': 'cross_jurisdiction_copy',
                                    'message': f"Snapshot copied across jurisdictions: {source_jurisdiction} to {current_jurisdiction}",
                                    'source_jurisdiction': source_jurisdiction,
                                    'source_region': source_region_detected,
                                    'current_jurisdiction': current_jurisdiction
                                })
                            
                            compliance_details['region_compliance_checks'].append({
                                'check': 'cross_region_copy_compliance',
                                'source_region': source_region_detected,
                                'source_jurisdiction': source_jurisdiction,
                                'compliant': source_jurisdiction == current_jurisdiction if source_jurisdiction else False
                            })
                    else:
                        compliance_details['is_copied_snapshot'] = False
                    
                    # Check snapshot sharing permissions
                    try:
                        sharing_response = ec2_client.describe_snapshot_attribute(
                            SnapshotId=snapshot_id,
                            Attribute='createVolumePermission'
                        )
                        
                        create_volume_permissions = sharing_response.get('CreateVolumePermissions', [])
                        sharing_violations = []
                        
                        for permission in create_volume_permissions:
                            # Check for public sharing
                            if permission.get('Group') == 'all':
                                sharing_violations.append({
                                    'type': 'public_sharing',
                                    'message': 'Snapshot is publicly shared',
                                    'severity': 'HIGH'
                                })
                            
                            # Check for cross-account sharing
                            user_id = permission.get('UserId')
                            if user_id:
                                sharing_violations.append({
                                    'type': 'cross_account_sharing',
                                    'message': f'Snapshot shared with account: {user_id}',
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
                            'total_permissions': len(create_volume_permissions),
                            'sharing_violations': sharing_violations,
                            'is_public': any(p.get('Group') == 'all' for p in create_volume_permissions)
                        }
                        
                    except Exception as sharing_error:
                        logger.warning(f"Failed to check sharing permissions for snapshot {snapshot_id}: {sharing_error}")
                        compliance_details['sharing_analysis'] = {'error': str(sharing_error)}
                    
                    # Check if volume source is cross-region
                    volume_id = snapshot.get('VolumeId')
                    if volume_id:
                        try:
                            volumes_response = ec2_client.describe_volumes(VolumeIds=[volume_id])
                            for volume in volumes_response.get('Volumes', []):
                                volume_az = volume.get('AvailabilityZone')
                                if volume_az and not volume_az.startswith(region_name):
                                    region_violations.append({
                                        'violation_type': 'cross_region_volume_source',
                                        'message': f"Snapshot created from volume in different region: {volume_az}",
                                        'volume_az': volume_az,
                                        'volume_id': volume_id
                                    })
                        except ec2_client.exceptions.ClientError:
                            # Volume might not exist anymore, which is normal for snapshots
                            pass
                        except Exception as vol_error:
                            logger.warning(f"Failed to check source volume {volume_id}: {vol_error}")
                    
                    # Add general snapshot details
                    compliance_details['snapshot_details'] = {
                        'description': snapshot.get('Description'),
                        'state': snapshot.get('State'),
                        'start_time': snapshot.get('StartTime').isoformat() if snapshot.get('StartTime') else None,
                        'volume_size': snapshot.get('VolumeSize'),
                        'encrypted': snapshot.get('Encrypted', False),
                        'kms_key_id': snapshot.get('KmsKeyId'),
                        'owner_id': snapshot.get('OwnerId'),
                        'volume_id': volume_id
                    }
                    
                    compliance_details['tags'] = {
                        'data_jurisdiction': data_jurisdiction,
                        'data_residency': data_residency,
                        'compliance_region': compliance_region,
                        'source_region': source_region
                    }
                    
                    # Determine compliance status
                    high_risk_violations = [v for v in region_violations if v.get('violation_type') in 
                                          ['cross_jurisdiction_copy', 'copy_from_unapproved_region', 'sharing_violation']]
                    
                    if high_risk_violations or len(region_violations) > 0:
                        findings.append({
                            "region": region_name,
                            "profile": profile_name or "default",
                            "resource_type": "ec2_snapshot",
                            "resource_id": snapshot_id,
                            "status": "NON_COMPLIANT",
                            "risk_level": "HIGH",
                            "recommendation": "Ensure EBS snapshot complies with cross-region copy restrictions",
                            "details": {
                                **compliance_details,
                                "violation": f"Snapshot has {len(region_violations)} region compliance violations",
                                "region_violations": region_violations,
                                "high_risk_violations": high_risk_violations
                            }
                        })
                    else:
                        findings.append({
                            "region": region_name,
                            "profile": profile_name or "default",
                            "resource_type": "ec2_snapshot",
                            "resource_id": snapshot_id,
                            "status": "COMPLIANT",
                            "risk_level": "HIGH",
                            "recommendation": "EBS snapshot complies with cross-region copy restrictions",
                            "details": compliance_details
                        })
                        
                except Exception as snapshot_error:
                    logger.warning(f"Failed to check snapshot {snapshot_id}: {snapshot_error}")
                    findings.append({
                        "region": region_name,
                        "profile": profile_name or "default",
                        "resource_type": "ec2_snapshot",
                        "resource_id": snapshot_id,
                        "status": "ERROR",
                        "risk_level": "HIGH",
                        "recommendation": "Unable to check snapshot cross-region copy compliance",
                        "details": {
                            "snapshot_id": snapshot_id,
                            "error": str(snapshot_error)
                        }
                    })
        
        logger.info(f"Completed checking ec2_snapshot_cross_region_copy_restricted. Found {len(findings)} findings.")
        
    except Exception as e:
        logger.error(f"Failed to check ec2_snapshot_cross_region_copy_restricted: {e}")
        findings.append({
            "region": region_name,
            "profile": profile_name or "default",
            "resource_type": "ec2_snapshot",
            "resource_id": "unknown",
            "status": "ERROR",
            "risk_level": "HIGH",
            "recommendation": "Fix API access issues",
            "details": {
                "error": str(e)
            }
        })
    
    return findings

def ec2_snapshot_cross_region_copy_restricted(region_name: str, profile_name: str = None) -> Dict[str, Any]:
    """
    Main function wrapper for ec2_snapshot_cross_region_copy_restricted.
    
    Args:
        region_name (str): AWS region name
        profile_name (str): AWS profile name (optional)
        
    Returns:
        Dict: Results summary
    """
    COMPLIANCE_DATA = load_rule_metadata("ec2_snapshot_cross_region_copy_restricted")
    
    # TODO: Implement SecurityEngine integration when available
    # from data_security_engine import SecurityEngine
    # engine = SecurityEngine(COMPLIANCE_DATA)
    # return engine.run_check(region_name, profile_name, ec2_snapshot_cross_region_copy_restricted_check)
    
    # Current implementation
    findings = ec2_snapshot_cross_region_copy_restricted_check(region_name, profile_name)
    
    # Calculate compliance statistics
    total_findings = len(findings)
    compliant_findings = len([f for f in findings if f['status'] == 'COMPLIANT'])
    non_compliant_findings = len([f for f in findings if f['status'] == 'NON_COMPLIANT'])
    error_findings = len([f for f in findings if f['status'] == 'ERROR'])
    
    return {
        "function_name": "ec2_snapshot_cross_region_copy_restricted",
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
    """CLI entry point for ec2_snapshot_cross_region_copy_restricted."""
    # TODO: Implement setup_command_line_interface() when data_security_engine is available
    # from data_security_engine import setup_command_line_interface, save_results, exit_with_status
    # args = setup_command_line_interface()
    # results = ec2_snapshot_cross_region_copy_restricted(args.region, args.profile)
    # save_results(results, args.output_file)
    # exit_with_status(results)
    
    # Current CLI implementation
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Ensure EBS snapshots are copied only to approved regions that meet data residency requirements."
    )
    parser.add_argument("--region", default="us-east-1", help="AWS region")
    parser.add_argument("--profile", help="AWS profile name")
    parser.add_argument("--output", help="Output file for results (JSON format)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        results = ec2_snapshot_cross_region_copy_restricted(args.region, args.profile)
        
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

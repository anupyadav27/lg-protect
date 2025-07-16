#!/usr/bin/env python3
"""
data_security_aws - ec2_dedicated_host_region_compliance

Ensure EC2 dedicated hosts are allocated only in approved regions to meet data residency requirements.
"""

# Rule Metadata from YAML:
# Function Name: ec2_dedicated_host_region_compliance
# Capability: DATA_RESIDENCY
# Service: EC2
# Subservice: REGION
# Description: Ensure EC2 dedicated hosts are allocated only in approved regions to meet data residency requirements.
# Risk Level: MEDIUM
# Recommendation: Ensure dedicated hosts comply with region restrictions
# API Function: client = boto3.client('ec2')
# User Function: ec2_dedicated_host_region_compliance()

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
        "function_name": "ec2_dedicated_host_region_compliance",
        "title": "Ensure dedicated hosts comply with region restrictions",
        "description": "Ensure EC2 dedicated hosts are allocated only in approved regions to meet data residency requirements.",
        "capability": "data_residency",
        "service": "ec2",
        "subservice": "region",
        "risk": "MEDIUM",
        "existing": False
    }

def ec2_dedicated_host_region_compliance_check(region_name: str, profile_name: str = None) -> List[Dict[str, Any]]:
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
                "recommendation": "Dedicated hosts should not be allocated in non-approved regions",
                "details": {
                    "current_region": region_name,
                    "violation": f"Region {region_name} is not in any approved jurisdiction",
                    "approved_regions": approved_regions
                }
            })
            return findings
        
        # Get all dedicated hosts in the region
        try:
            hosts_response = ec2_client.describe_hosts()
            hosts = hosts_response.get('Hosts', [])
            
            if not hosts:
                # No dedicated hosts found - this is compliant
                findings.append({
                    "region": region_name,
                    "profile": profile_name or "default",
                    "resource_type": "ec2_dedicated_host",
                    "resource_id": f"region:{region_name}",
                    "status": "COMPLIANT",
                    "risk_level": "MEDIUM",
                    "recommendation": "No dedicated hosts found in region",
                    "details": {
                        "current_region": region_name,
                        "current_jurisdiction": current_jurisdiction,
                        "host_count": 0
                    }
                })
                return findings
            
            for host in hosts:
                host_id = host.get('HostId')
                
                try:
                    region_violations = []
                    compliance_details = {
                        'host_id': host_id,
                        'current_region': region_name,
                        'current_jurisdiction': current_jurisdiction,
                        'region_compliance_checks': []
                    }
                    
                    # Get host tags to check for compliance requirements
                    tags = {tag.get('Key'): tag.get('Value') for tag in host.get('Tags', [])}
                    
                    # Check if host has data jurisdiction tags
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
                                        'message': f"Host tagged for {data_jurisdiction} jurisdiction but allocated in {current_jurisdiction} region",
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
                                'message': f"Host requires data residency in {data_residency} but allocated in {region_name}",
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
                                'message': f"Host tagged for compliance in {compliance_region} but allocated in {region_name.upper()}",
                                'required_region': compliance_region,
                                'current_region': region_name.upper()
                            })
                        
                        compliance_details['region_compliance_checks'].append({
                            'check': 'compliance_region_tag',
                            'required_region': compliance_region,
                            'compliant': compliance_region == region_name.upper()
                        })
                    
                    # Check availability zone compliance within region
                    availability_zone = host.get('AvailabilityZone')
                    if availability_zone:
                        if not availability_zone.startswith(region_name):
                            region_violations.append({
                                'violation_type': 'az_region_mismatch',
                                'message': f"Host availability zone {availability_zone} does not match region {region_name}",
                                'host_az': availability_zone,
                                'expected_region': region_name
                            })
                        
                        # Check for specific AZ restrictions if tagged
                        required_az = tags.get('RequiredAvailabilityZone', '')
                        if required_az and required_az != availability_zone:
                            region_violations.append({
                                'violation_type': 'az_requirement_violation',
                                'message': f"Host not in required availability zone: {required_az}",
                                'current_az': availability_zone,
                                'required_az': required_az
                            })
                    
                    # Check instances running on the host for cross-region violations
                    instances = host.get('Instances', [])
                    if instances:
                        for instance in instances:
                            instance_id = instance.get('InstanceId')
                            try:
                                instance_response = ec2_client.describe_instances(InstanceIds=[instance_id])
                                for reservation in instance_response.get('Reservations', []):
                                    for inst_detail in reservation.get('Instances', []):
                                        inst_az = inst_detail.get('Placement', {}).get('AvailabilityZone')
                                        if inst_az and not inst_az.startswith(region_name):
                                            region_violations.append({
                                                'violation_type': 'cross_region_instance',
                                                'message': f"Instance {instance_id} on dedicated host is in different region",
                                                'instance_id': instance_id,
                                                'instance_az': inst_az,
                                                'host_region': region_name
                                            })
                                        
                                        # Check instance tags for jurisdiction requirements
                                        inst_tags = {tag.get('Key'): tag.get('Value') for tag in inst_detail.get('Tags', [])}
                                        inst_jurisdiction = inst_tags.get('DataJurisdiction', '').upper()
                                        if inst_jurisdiction and inst_jurisdiction != current_jurisdiction:
                                            region_violations.append({
                                                'violation_type': 'instance_jurisdiction_mismatch',
                                                'message': f"Instance {instance_id} requires {inst_jurisdiction} jurisdiction but host is in {current_jurisdiction}",
                                                'instance_id': instance_id,
                                                'instance_jurisdiction': inst_jurisdiction,
                                                'host_jurisdiction': current_jurisdiction
                                            })
                            except Exception as inst_error:
                                logger.warning(f"Failed to check instance {instance_id}: {inst_error}")
                    
                    # Check host resource allocation and capacity
                    host_properties = host.get('HostProperties', {})
                    instance_type = host_properties.get('InstanceType')
                    total_vcpus = host_properties.get('TotalVCpus', 0)
                    sockets = host_properties.get('Sockets', 0)
                    cores = host_properties.get('Cores', 0)
                    
                    # Add host details
                    compliance_details['host_details'] = {
                        'state': host.get('State'),
                        'allocation': host.get('Allocation'),
                        'availability_zone': availability_zone,
                        'instance_type': instance_type,
                        'total_vcpus': total_vcpus,
                        'sockets': sockets,
                        'cores': cores,
                        'host_recovery': host.get('HostRecovery'),
                        'instance_family': host_properties.get('InstanceFamily'),
                        'allocation_time': host.get('AllocationTime').isoformat() if host.get('AllocationTime') else None,
                        'release_time': host.get('ReleaseTime').isoformat() if host.get('ReleaseTime') else None
                    }
                    
                    compliance_details['host_tags'] = tags
                    compliance_details['instances_on_host'] = [{
                        'instance_id': inst.get('InstanceId'),
                        'instance_type': inst.get('InstanceType')
                    } for inst in instances]
                    
                    # Check for compliance-specific requirements
                    if data_jurisdiction in ['EU', 'UK'] or any(framework in tags.get('ComplianceFramework', '').upper() 
                                                              for framework in ['GDPR', 'DPA']):
                        # EU/UK specific checks
                        if not tags.get('DataController'):
                            region_violations.append({
                                'violation_type': 'missing_data_controller',
                                'message': 'EU/UK dedicated hosts should have DataController tag',
                                'jurisdiction': data_jurisdiction
                            })
                        
                        if not tags.get('LegalBasis'):
                            region_violations.append({
                                'violation_type': 'missing_legal_basis',
                                'message': 'EU/UK dedicated hosts should have LegalBasis tag',
                                'jurisdiction': data_jurisdiction
                            })
                    
                    # Check for US compliance requirements
                    if data_jurisdiction == 'US' and any(framework in tags.get('ComplianceFramework', '').upper() 
                                                        for framework in ['HIPAA', 'SOX', 'FISMA']):
                        if not tags.get('ComplianceOfficer'):
                            region_violations.append({
                                'violation_type': 'missing_compliance_officer',
                                'message': 'US compliance-regulated hosts should have ComplianceOfficer tag',
                                'jurisdiction': data_jurisdiction
                            })
                    
                    # Determine compliance status
                    high_risk_violations = [v for v in region_violations if v.get('violation_type') in 
                                          ['jurisdiction_mismatch', 'cross_region_instance', 'residency_mismatch']]
                    
                    if high_risk_violations or len(region_violations) > 0:
                        findings.append({
                            "region": region_name,
                            "profile": profile_name or "default",
                            "resource_type": "ec2_dedicated_host",
                            "resource_id": host_id,
                            "status": "NON_COMPLIANT",
                            "risk_level": "MEDIUM",
                            "recommendation": "Ensure dedicated host complies with region restrictions",
                            "details": {
                                **compliance_details,
                                "violation": f"Host has {len(region_violations)} region compliance violations",
                                "region_violations": region_violations,
                                "high_risk_violations": high_risk_violations
                            }
                        })
                    else:
                        findings.append({
                            "region": region_name,
                            "profile": profile_name or "default",
                            "resource_type": "ec2_dedicated_host",
                            "resource_id": host_id,
                            "status": "COMPLIANT",
                            "risk_level": "MEDIUM",
                            "recommendation": "Dedicated host complies with region restrictions",
                            "details": compliance_details
                        })
                        
                except Exception as host_error:
                    logger.warning(f"Failed to check dedicated host {host_id}: {host_error}")
                    findings.append({
                        "region": region_name,
                        "profile": profile_name or "default",
                        "resource_type": "ec2_dedicated_host",
                        "resource_id": host_id,
                        "status": "ERROR",
                        "risk_level": "MEDIUM",
                        "recommendation": "Unable to check dedicated host region compliance",
                        "details": {
                            "host_id": host_id,
                            "error": str(host_error)
                        }
                    })
                    
        except Exception as hosts_error:
            logger.warning(f"Failed to describe hosts: {hosts_error}")
            findings.append({
                "region": region_name,
                "profile": profile_name or "default",
                "resource_type": "ec2_dedicated_host",
                "resource_id": "unknown",
                "status": "ERROR",
                "risk_level": "MEDIUM",
                "recommendation": "Unable to retrieve dedicated hosts",
                "details": {
                    "error": str(hosts_error)
                }
            })
        
        logger.info(f"Completed checking ec2_dedicated_host_region_compliance. Found {len(findings)} findings.")
        
    except Exception as e:
        logger.error(f"Failed to check ec2_dedicated_host_region_compliance: {e}")
        findings.append({
            "region": region_name,
            "profile": profile_name or "default",
            "resource_type": "ec2_dedicated_host",
            "resource_id": "unknown",
            "status": "ERROR",
            "risk_level": "MEDIUM",
            "recommendation": "Fix API access issues",
            "details": {
                "error": str(e)
            }
        })
    
    return findings

def ec2_dedicated_host_region_compliance(region_name: str, profile_name: str = None) -> Dict[str, Any]:
    """
    Main function wrapper for ec2_dedicated_host_region_compliance.
    
    Args:
        region_name (str): AWS region name
        profile_name (str): AWS profile name (optional)
        
    Returns:
        Dict: Results summary
    """
    COMPLIANCE_DATA = load_rule_metadata("ec2_dedicated_host_region_compliance")
    
    # TODO: Implement SecurityEngine integration when available
    # from data_security_engine import SecurityEngine
    # engine = SecurityEngine(COMPLIANCE_DATA)
    # return engine.run_check(region_name, profile_name, ec2_dedicated_host_region_compliance_check)
    
    # Current implementation
    findings = ec2_dedicated_host_region_compliance_check(region_name, profile_name)
    
    # Calculate compliance statistics
    total_findings = len(findings)
    compliant_findings = len([f for f in findings if f['status'] == 'COMPLIANT'])
    non_compliant_findings = len([f for f in findings if f['status'] == 'NON_COMPLIANT'])
    error_findings = len([f for f in findings if f['status'] == 'ERROR'])
    
    return {
        "function_name": "ec2_dedicated_host_region_compliance",
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
    """CLI entry point for ec2_dedicated_host_region_compliance."""
    # TODO: Implement setup_command_line_interface() when data_security_engine is available
    # from data_security_engine import setup_command_line_interface, save_results, exit_with_status
    # args = setup_command_line_interface()
    # results = ec2_dedicated_host_region_compliance(args.region, args.profile)
    # save_results(results, args.output_file)
    # exit_with_status(results)
    
    # Current CLI implementation
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Ensure EC2 dedicated hosts are allocated only in approved regions to meet data residency requirements."
    )
    parser.add_argument("--region", default="us-east-1", help="AWS region")
    parser.add_argument("--profile", help="AWS profile name")
    parser.add_argument("--output", help="Output file for results (JSON format)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        results = ec2_dedicated_host_region_compliance(args.region, args.profile)
        
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

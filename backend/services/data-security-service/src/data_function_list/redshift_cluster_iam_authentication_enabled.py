#!/usr/bin/env python3
"""
data_security_aws - redshift_cluster_iam_authentication_enabled

Enable IAM authentication for Redshift clusters to centralize access control and eliminate database passwords.
"""

# Rule Metadata from YAML:
# Function Name: redshift_cluster_iam_authentication_enabled
# Capability: ACCESS_GOVERNANCE
# Service: REDSHIFT
# Subservice: AUTHENTICATION
# Description: Enable IAM authentication for Redshift clusters to centralize access control and eliminate database passwords.
# Risk Level: MEDIUM
# Recommendation: Enable IAM authentication for Redshift clusters
# API Function: client = boto3.client('redshift')
# User Function: redshift_cluster_iam_authentication_enabled()

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
        "function_name": "redshift_cluster_iam_authentication_enabled",
        "title": "Enable IAM authentication for Redshift clusters",
        "description": "Enable IAM authentication for Redshift clusters to centralize access control and eliminate database passwords.",
        "capability": "access_governance",
        "service": "redshift",
        "subservice": "authentication",
        "risk": "MEDIUM",
        "existing": False
    }

def redshift_cluster_iam_authentication_enabled_check(region_name: str, profile_name: str = None) -> List[Dict[str, Any]]:
    """
    Check Redshift clusters for IAM authentication compliance.
    
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
        redshift_client = session.client('redshift', region_name=region_name)
        
        logger.info(f"Checking Redshift resources for IAM authentication compliance in region {region_name}")
        
        # Get all Redshift clusters in the region
        paginator = redshift_client.get_paginator('describe_clusters')
        
        for page in paginator.paginate():
            for cluster in page.get('Clusters', []):
                cluster_identifier = cluster.get('ClusterIdentifier')
                cluster_arn = f"arn:aws:redshift:{region_name}:{cluster.get('OwnerAccount', 'unknown')}:cluster:{cluster_identifier}"
                
                try:
                    authentication_violations = []
                    authentication_features = []
                    
                    # Check IAM database authentication status
                    iam_database_authentication_enabled = cluster.get('IamDatabaseAuthenticationEnabled', False)
                    
                    if not iam_database_authentication_enabled:
                        authentication_violations.append("IAM database authentication is not enabled")
                    else:
                        authentication_features.append({
                            'feature': 'IAM Database Authentication',
                            'enabled': True
                        })
                    
                    # Check cluster parameter group for IAM authentication settings
                    parameter_groups = cluster.get('ClusterParameterGroups', [])
                    iam_auth_parameter_configured = False
                    
                    for param_group in parameter_groups:
                        param_group_name = param_group.get('ParameterGroupName')
                        param_status = param_group.get('ParameterApplyStatus')
                        
                        try:
                            # Get parameter group details
                            param_response = redshift_client.describe_cluster_parameters(
                                ParameterGroupName=param_group_name
                            )
                            
                            parameters = param_response.get('Parameters', [])
                            
                            # Look for IAM-related parameters
                            for parameter in parameters:
                                param_name = parameter.get('ParameterName', '')
                                param_value = parameter.get('ParameterValue', '')
                                
                                # Check for SSL enforcement (important for IAM auth)
                                if param_name == 'require_ssl' and param_value.lower() == 'true':
                                    authentication_features.append({
                                        'feature': 'SSL Required',
                                        'parameter_group': param_group_name,
                                        'value': param_value
                                    })
                                
                                # Check for database authentication timeout
                                if param_name in ['iam_database_authentication_timeout', 'authentication_timeout']:
                                    authentication_features.append({
                                        'feature': 'Authentication Timeout',
                                        'parameter_group': param_group_name,
                                        'parameter': param_name,
                                        'value': param_value
                                    })
                                    iam_auth_parameter_configured = True
                                
                                # Check for connection limit (security measure)
                                if param_name == 'max_connections':
                                    authentication_features.append({
                                        'feature': 'Connection Limit',
                                        'parameter_group': param_group_name,
                                        'value': param_value
                                    })
                            
                        except Exception as param_error:
                            logger.warning(f"Failed to check parameter group {param_group_name}: {param_error}")
                            authentication_violations.append(f"Unable to verify parameter group {param_group_name} configuration")
                    
                    # Check cluster security and networking configuration
                    cluster_security_groups = cluster.get('ClusterSecurityGroups', [])
                    vpc_security_group_ids = cluster.get('VpcSecurityGroups', [])
                    
                    # Check if cluster is in VPC (more secure)
                    vpc_id = cluster.get('VpcId')
                    if vpc_id:
                        authentication_features.append({
                            'feature': 'VPC Deployment',
                            'vpc_id': vpc_id,
                            'security_groups_count': len(vpc_security_group_ids)
                        })
                    else:
                        authentication_violations.append("Cluster is not deployed in VPC (less secure)")
                    
                    # Check if cluster is publicly accessible
                    publicly_accessible = cluster.get('PubliclyAccessible', False)
                    if publicly_accessible:
                        authentication_violations.append("Cluster is publicly accessible - increases security risk")
                    else:
                        authentication_features.append({
                            'feature': 'Private Access',
                            'publicly_accessible': False
                        })
                    
                    # Check encryption status (related to secure authentication)
                    encrypted = cluster.get('Encrypted', False)
                    if encrypted:
                        authentication_features.append({
                            'feature': 'Encryption at Rest',
                            'enabled': True,
                            'kms_key_id': cluster.get('KmsKeyId')
                        })
                    else:
                        authentication_violations.append("Cluster encryption at rest is not enabled")
                    
                    # Check cluster version (newer versions have better IAM support)
                    cluster_version = cluster.get('ClusterVersion', '')
                    if cluster_version:
                        # Extract major version number
                        try:
                            version_number = float(cluster_version.split('.')[0] + '.' + cluster_version.split('.')[1])
                            if version_number >= 1.0:  # Modern Redshift versions
                                authentication_features.append({
                                    'feature': 'Modern Redshift Version',
                                    'version': cluster_version
                                })
                            else:
                                authentication_violations.append(f"Older Redshift version {cluster_version} may have limited IAM authentication features")
                        except (ValueError, IndexError):
                            logger.warning(f"Could not parse cluster version: {cluster_version}")
                    
                    # Check cluster status
                    cluster_status = cluster.get('ClusterStatus', '').lower()
                    if cluster_status != 'available':
                        authentication_violations.append(f"Cluster is not in 'available' status: {cluster_status}")
                    
                    # Check for enhanced VPC routing (affects authentication flow)
                    enhanced_vpc_routing = cluster.get('EnhancedVpcRouting', False)
                    if enhanced_vpc_routing:
                        authentication_features.append({
                            'feature': 'Enhanced VPC Routing',
                            'enabled': True
                        })
                    
                    # Check cluster subnet group for network isolation
                    cluster_subnet_group_name = cluster.get('ClusterSubnetGroupName')
                    if cluster_subnet_group_name:
                        try:
                            subnet_response = redshift_client.describe_cluster_subnet_groups(
                                ClusterSubnetGroupName=cluster_subnet_group_name
                            )
                            
                            subnet_groups = subnet_response.get('ClusterSubnetGroups', [])
                            for subnet_group in subnet_groups:
                                subnets = subnet_group.get('Subnets', [])
                                authentication_features.append({
                                    'feature': 'Subnet Group Configuration',
                                    'subnet_group_name': cluster_subnet_group_name,
                                    'subnets_count': len(subnets),
                                    'vpc_id': subnet_group.get('VpcId')
                                })
                                
                        except Exception as subnet_error:
                            logger.warning(f"Failed to check subnet group {cluster_subnet_group_name}: {subnet_error}")
                    
                    # Check cluster logging configuration
                    logging_status = cluster.get('LoggingStatus', {})
                    logging_enabled = logging_status.get('LoggingEnabled', False)
                    
                    if logging_enabled:
                        authentication_features.append({
                            'feature': 'Audit Logging',
                            'enabled': True,
                            'log_destination_type': logging_status.get('LogDestinationType'),
                            'bucket_name': logging_status.get('BucketName'),
                            's3_key_prefix': logging_status.get('S3KeyPrefix')
                        })
                    else:
                        authentication_violations.append("Audit logging is not enabled - authentication events won't be logged")
                    
                    # Check for manual snapshots (backup strategy for authentication configuration)
                    try:
                        snapshots_response = redshift_client.describe_cluster_snapshots(
                            ClusterIdentifier=cluster_identifier,
                            SnapshotType='manual',
                            MaxRecords=5
                        )
                        
                        manual_snapshots = snapshots_response.get('Snapshots', [])
                        if manual_snapshots:
                            authentication_features.append({
                                'feature': 'Manual Snapshots Available',
                                'snapshots_count': len(manual_snapshots)
                            })
                        
                    except Exception as snapshot_error:
                        logger.warning(f"Failed to check snapshots for cluster {cluster_identifier}: {snapshot_error}")
                    
                    # Check cluster tags for compliance requirements
                    try:
                        tags_response = redshift_client.describe_tags(
                            ResourceName=cluster_arn,
                            ResourceType='cluster'
                        )
                        
                        tags = tags_response.get('TaggedResources', [])
                        if tags:
                            tag_list = []
                            for tag_resource in tags:
                                for tag in tag_resource.get('Tag', []):
                                    tag_key = tag.get('Key', '').upper()
                                    if any(keyword in tag_key for keyword in 
                                           ['IAM', 'AUTH', 'SECURITY', 'COMPLIANCE']):
                                        tag_list.append({
                                            'key': tag.get('Key'),
                                            'value': tag.get('Value')
                                        })
                            
                            if tag_list:
                                authentication_features.append({
                                    'feature': 'Security-related Tags',
                                    'tags': tag_list
                                })
                        
                    except Exception as tags_error:
                        logger.warning(f"Failed to check tags for cluster {cluster_identifier}: {tags_error}")
                    
                    # Calculate authentication compliance score
                    auth_score = len(authentication_features)
                    auth_issues = len(authentication_violations)
                    
                    # Determine compliance status
                    if not iam_database_authentication_enabled:
                        # Critical violation - IAM auth not enabled
                        findings.append({
                            "region": region_name,
                            "profile": profile_name or "default",
                            "resource_type": "redshift_cluster",
                            "resource_id": cluster_arn,
                            "status": "NON_COMPLIANT",
                            "risk_level": "MEDIUM",
                            "recommendation": "Enable IAM database authentication for Redshift cluster",
                            "details": {
                                "cluster_identifier": cluster_identifier,
                                "cluster_arn": cluster_arn,
                                "violation": "IAM database authentication is not enabled",
                                "authentication_violations": authentication_violations,
                                "configured_features": authentication_features,
                                "authentication_score": auth_score,
                                "cluster_status": cluster_status,
                                "publicly_accessible": publicly_accessible,
                                "encrypted": encrypted,
                                "vpc_deployment": bool(vpc_id),
                                "logging_enabled": logging_enabled,
                                "cluster_version": cluster_version
                            }
                        })
                    elif auth_issues > 2:  # Minor issues but IAM auth is enabled
                        findings.append({
                            "region": region_name,
                            "profile": profile_name or "default",
                            "resource_type": "redshift_cluster",
                            "resource_id": cluster_arn,
                            "status": "NON_COMPLIANT",
                            "risk_level": "LOW",
                            "recommendation": "Address remaining authentication security concerns for Redshift cluster",
                            "details": {
                                "cluster_identifier": cluster_identifier,
                                "cluster_arn": cluster_arn,
                                "violation": f"IAM authentication enabled but {auth_issues} security concerns remain",
                                "authentication_violations": authentication_violations,
                                "configured_features": authentication_features,
                                "authentication_score": auth_score,
                                "iam_database_authentication_enabled": True,
                                "cluster_status": cluster_status,
                                "publicly_accessible": publicly_accessible,
                                "encrypted": encrypted,
                                "vpc_deployment": bool(vpc_id),
                                "logging_enabled": logging_enabled,
                                "cluster_version": cluster_version
                            }
                        })
                    else:
                        findings.append({
                            "region": region_name,
                            "profile": profile_name or "default",
                            "resource_type": "redshift_cluster",
                            "resource_id": cluster_arn,
                            "status": "COMPLIANT",
                            "risk_level": "MEDIUM",
                            "recommendation": "Redshift cluster has proper IAM authentication configuration",
                            "details": {
                                "cluster_identifier": cluster_identifier,
                                "cluster_arn": cluster_arn,
                                "configured_features": authentication_features,
                                "authentication_score": auth_score,
                                "minor_issues": authentication_violations if authentication_violations else None,
                                "iam_database_authentication_enabled": True,
                                "cluster_status": cluster_status,
                                "publicly_accessible": publicly_accessible,
                                "encrypted": encrypted,
                                "vpc_deployment": bool(vpc_id),
                                "logging_enabled": logging_enabled,
                                "cluster_version": cluster_version
                            }
                        })
                        
                except Exception as cluster_error:
                    logger.warning(f"Failed to check cluster {cluster_identifier}: {cluster_error}")
                    findings.append({
                        "region": region_name,
                        "profile": profile_name or "default",
                        "resource_type": "redshift_cluster",
                        "resource_id": cluster_arn,
                        "status": "ERROR",
                        "risk_level": "MEDIUM",
                        "recommendation": "Unable to check IAM authentication configuration",
                        "details": {
                            "cluster_identifier": cluster_identifier,
                            "cluster_arn": cluster_arn,
                            "error": str(cluster_error)
                        }
                    })
        
        logger.info(f"Completed checking redshift_cluster_iam_authentication_enabled. Found {len(findings)} findings.")
        
    except Exception as e:
        logger.error(f"Failed to check redshift_cluster_iam_authentication_enabled: {e}")
        findings.append({
            "region": region_name,
            "profile": profile_name or "default",
            "resource_type": "redshift_cluster",
            "resource_id": "unknown",
            "status": "ERROR",
            "risk_level": "MEDIUM",
            "recommendation": "Fix API access issues",
            "details": {
                "error": str(e)
            }
        })
    
    return findings

def redshift_cluster_iam_authentication_enabled(region_name: str, profile_name: str = None) -> Dict[str, Any]:
    """
    Main function wrapper for redshift_cluster_iam_authentication_enabled.
    
    Args:
        region_name (str): AWS region name
        profile_name (str): AWS profile name (optional)
        
    Returns:
        Dict: Results summary
    """
    COMPLIANCE_DATA = load_rule_metadata("redshift_cluster_iam_authentication_enabled")
    
    # TODO: Implement SecurityEngine integration when available
    # from data_security_engine import SecurityEngine
    # engine = SecurityEngine(COMPLIANCE_DATA)
    # return engine.run_check(region_name, profile_name, redshift_cluster_iam_authentication_enabled_check)
    
    # Current implementation
    findings = redshift_cluster_iam_authentication_enabled_check(region_name, profile_name)
    
    # Calculate compliance statistics
    total_findings = len(findings)
    compliant_findings = len([f for f in findings if f['status'] == 'COMPLIANT'])
    non_compliant_findings = len([f for f in findings if f['status'] == 'NON_COMPLIANT'])
    error_findings = len([f for f in findings if f['status'] == 'ERROR'])
    
    return {
        "function_name": "redshift_cluster_iam_authentication_enabled",
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
    """CLI entry point for redshift_cluster_iam_authentication_enabled."""
    # TODO: Implement setup_command_line_interface() when data_security_engine is available
    # from data_security_engine import setup_command_line_interface, save_results, exit_with_status
    # args = setup_command_line_interface()
    # results = redshift_cluster_iam_authentication_enabled(args.region, args.profile)
    # save_results(results, args.output_file)
    # exit_with_status(results)
    
    # Current CLI implementation
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Enable IAM authentication for Redshift clusters to centralize access control and eliminate database passwords."
    )
    parser.add_argument("--region", default="us-east-1", help="AWS region")
    parser.add_argument("--profile", help="AWS profile name")
    parser.add_argument("--output", help="Output file for results (JSON format)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        results = redshift_cluster_iam_authentication_enabled(args.region, args.profile)
        
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

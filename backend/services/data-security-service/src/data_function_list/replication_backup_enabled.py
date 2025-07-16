#!/usr/bin/env python3
"""
data_security_aws - replication_backup_enabled

Ensure replication configurations are backed up to prevent data loss and maintain disaster recovery capabilities.
"""

# Rule Metadata from YAML:
# Function Name: replication_backup_enabled
# Capability: DATA_PROTECTION
# Service: REPLICATION
# Subservice: BACKUP
# Description: Ensure replication configurations are backed up to prevent data loss and maintain disaster recovery capabilities.
# Risk Level: MEDIUM
# Recommendation: Enable backup for replication configurations
# API Function: client = boto3.client('replication')
# User Function: replication_backup_enabled()

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
        "function_name": "replication_backup_enabled",
        "title": "Enable backup for replication configurations",
        "description": "Ensure replication configurations are backed up to prevent data loss and maintain disaster recovery capabilities.",
        "capability": "data_protection",
        "service": "replication",
        "subservice": "backup",
        "risk": "MEDIUM",
        "existing": False
    }

def replication_backup_enabled_check(region_name: str, profile_name: str = None) -> List[Dict[str, Any]]:
    """
    Check replication resources for backup compliance across AWS services.
    
    Args:
        region_name (str): AWS region name
        profile_name (str): AWS profile name (optional)
        
    Returns:
        List[Dict]: List of compliance findings
    """
    findings = []
    
    try:
        # Initialize boto3 session
        session = boto3.Session(profile_name=profile_name)
        
        logger.info(f"Checking replication backup configurations for data protection compliance in region {region_name}")
        
        # Check S3 Cross-Region Replication backup configurations
        try:
            s3_client = session.client('s3', region_name=region_name)
            
            # Get all S3 buckets
            buckets_response = s3_client.list_buckets()
            buckets = buckets_response.get('Buckets', [])
            
            for bucket in buckets:
                bucket_name = bucket.get('Name')
                
                try:
                    # Check bucket replication configuration
                    try:
                        replication_response = s3_client.get_bucket_replication(Bucket=bucket_name)
                        replication_config = replication_response.get('ReplicationConfiguration', {})
                        
                        backup_violations = []
                        backup_features = []
                        
                        # Check if replication rules have backup features
                        rules = replication_config.get('Rules', [])
                        
                        for rule in rules:
                            rule_id = rule.get('ID', 'Unknown')
                            status = rule.get('Status')
                            destination = rule.get('Destination', {})
                            
                            if status != 'Enabled':
                                backup_violations.append(f"Replication rule {rule_id} is not enabled")
                                continue
                            
                            # Check destination bucket configuration
                            dest_bucket = destination.get('Bucket', '').replace('arn:aws:s3:::', '')
                            storage_class = destination.get('StorageClass')
                            
                            if storage_class:
                                backup_features.append({
                                    'feature': 'Storage Class Transition',
                                    'rule_id': rule_id,
                                    'storage_class': storage_class,
                                    'destination_bucket': dest_bucket
                                })
                            
                            # Check for versioning in destination (important for backup)
                            try:
                                dest_versioning = s3_client.get_bucket_versioning(Bucket=dest_bucket)
                                versioning_status = dest_versioning.get('Status')
                                
                                if versioning_status == 'Enabled':
                                    backup_features.append({
                                        'feature': 'Destination Versioning',
                                        'rule_id': rule_id,
                                        'destination_bucket': dest_bucket,
                                        'versioning_enabled': True
                                    })
                                else:
                                    backup_violations.append(f"Destination bucket {dest_bucket} does not have versioning enabled")
                            except Exception as dest_error:
                                backup_violations.append(f"Cannot verify destination bucket {dest_bucket} versioning: {str(dest_error)}")
                            
                            # Check for MFA delete protection
                            mfa_delete = dest_versioning.get('MfaDelete')
                            if mfa_delete == 'Enabled':
                                backup_features.append({
                                    'feature': 'MFA Delete Protection',
                                    'rule_id': rule_id,
                                    'destination_bucket': dest_bucket
                                })
                            
                            # Check for delete marker replication
                            delete_marker_replication = rule.get('DeleteMarkerReplication', {})
                            if delete_marker_replication.get('Status') == 'Enabled':
                                backup_features.append({
                                    'feature': 'Delete Marker Replication',
                                    'rule_id': rule_id
                                })
                            
                            # Check for replica modifications
                            replica_modifications = rule.get('ReplicaModifications', {})
                            if replica_modifications.get('Status') == 'Enabled':
                                backup_features.append({
                                    'feature': 'Replica Modifications',
                                    'rule_id': rule_id
                                })
                        
                        # Check source bucket backup features
                        try:
                            source_versioning = s3_client.get_bucket_versioning(Bucket=bucket_name)
                            if source_versioning.get('Status') != 'Enabled':
                                backup_violations.append("Source bucket versioning is not enabled")
                            else:
                                backup_features.append({
                                    'feature': 'Source Versioning',
                                    'enabled': True
                                })
                        except Exception as source_error:
                            backup_violations.append(f"Cannot verify source bucket versioning: {str(source_error)}")
                        
                        # Check for backup retention policies
                        try:
                            lifecycle_response = s3_client.get_bucket_lifecycle_configuration(Bucket=bucket_name)
                            lifecycle_rules = lifecycle_response.get('Rules', [])
                            
                            retention_configured = False
                            for lifecycle_rule in lifecycle_rules:
                                if lifecycle_rule.get('Status') == 'Enabled':
                                    transitions = lifecycle_rule.get('Transitions', [])
                                    if transitions:
                                        retention_configured = True
                                        backup_features.append({
                                            'feature': 'Lifecycle Retention',
                                            'rule_id': lifecycle_rule.get('ID'),
                                            'transitions_count': len(transitions)
                                        })
                            
                            if not retention_configured:
                                backup_violations.append("No lifecycle retention policies configured")
                                
                        except s3_client.exceptions.NoSuchLifecycleConfiguration:
                            backup_violations.append("No lifecycle configuration for backup retention")
                        except Exception as lifecycle_error:
                            logger.warning(f"Failed to check lifecycle for bucket {bucket_name}: {lifecycle_error}")
                        
                        # Determine compliance status
                        critical_violations = len([v for v in backup_violations if 'not enabled' in v.lower() or 'versioning' in v.lower()])
                        
                        if critical_violations > 0 or len(backup_violations) > len(backup_features):
                            findings.append({
                                "region": region_name,
                                "profile": profile_name or "default",
                                "resource_type": "s3_replication",
                                "resource_id": f"arn:aws:s3:::{bucket_name}",
                                "status": "NON_COMPLIANT",
                                "risk_level": "MEDIUM",
                                "recommendation": "Ensure S3 replication has proper backup configurations",
                                "details": {
                                    "bucket_name": bucket_name,
                                    "replication_rules_count": len(rules),
                                    "violation": f"Replication backup has {len(backup_violations)} configuration issues",
                                    "backup_violations": backup_violations,
                                    "configured_features": backup_features
                                }
                            })
                        else:
                            findings.append({
                                "region": region_name,
                                "profile": profile_name or "default",
                                "resource_type": "s3_replication",
                                "resource_id": f"arn:aws:s3:::{bucket_name}",
                                "status": "COMPLIANT",
                                "risk_level": "MEDIUM",
                                "recommendation": "S3 replication backup is properly configured",
                                "details": {
                                    "bucket_name": bucket_name,
                                    "replication_rules_count": len(rules),
                                    "configured_features": backup_features,
                                    "minor_issues": backup_violations if backup_violations else None
                                }
                            })
                            
                    except s3_client.exceptions.NoSuchReplicationConfiguration:
                        # No replication configured - not necessarily a violation
                        continue
                        
                except Exception as bucket_error:
                    logger.warning(f"Failed to check bucket {bucket_name}: {bucket_error}")
                    findings.append({
                        "region": region_name,
                        "profile": profile_name or "default",
                        "resource_type": "s3_replication",
                        "resource_id": f"arn:aws:s3:::{bucket_name}",
                        "status": "ERROR",
                        "risk_level": "MEDIUM",
                        "recommendation": "Unable to check S3 replication backup configuration",
                        "details": {
                            "bucket_name": bucket_name,
                            "error": str(bucket_error)
                        }
                    })
                    
        except Exception as s3_error:
            logger.warning(f"Failed to check S3 replication configurations: {s3_error}")
        
        # Check DynamoDB Global Tables backup configurations
        try:
            dynamodb_client = session.client('dynamodb', region_name=region_name)
            
            # Get all DynamoDB tables
            paginator = dynamodb_client.get_paginator('list_tables')
            
            for page in paginator.paginate():
                for table_name in page.get('TableNames', []):
                    try:
                        # Check if table is part of Global Tables
                        table_response = dynamodb_client.describe_table(TableName=table_name)
                        table = table_response.get('Table', {})
                        
                        replicas = table.get('Replicas', [])
                        global_table_version = table.get('GlobalTableVersion')
                        
                        if replicas or global_table_version:
                            backup_violations = []
                            backup_features = []
                            
                            # Check Point-in-Time Recovery for Global Table
                            try:
                                pitr_response = dynamodb_client.describe_continuous_backups(TableName=table_name)
                                pitr_description = pitr_response.get('ContinuousBackupsDescription', {})
                                pitr_status = pitr_description.get('PointInTimeRecoveryDescription', {}).get('PointInTimeRecoveryStatus')
                                
                                if pitr_status == 'ENABLED':
                                    backup_features.append({
                                        'feature': 'Point-in-Time Recovery',
                                        'enabled': True
                                    })
                                else:
                                    backup_violations.append("Point-in-Time Recovery not enabled for Global Table")
                                    
                            except Exception as pitr_error:
                                backup_violations.append(f"Cannot verify PITR status: {str(pitr_error)}")
                            
                            # Check backup retention for each replica
                            for replica in replicas:
                                replica_region = replica.get('RegionName')
                                replica_status = replica.get('ReplicaStatus')
                                
                                if replica_status == 'ACTIVE':
                                    backup_features.append({
                                        'feature': 'Active Replica',
                                        'region': replica_region
                                    })
                                else:
                                    backup_violations.append(f"Replica in {replica_region} is not active")
                            
                            # Check for backup policy
                            try:
                                backup_response = dynamodb_client.describe_backup_retention_policy(TableName=table_name)
                                retention_period = backup_response.get('BackupRetentionPeriod', 0)
                                
                                if retention_period > 0:
                                    backup_features.append({
                                        'feature': 'Backup Retention Policy',
                                        'retention_days': retention_period
                                    })
                                else:
                                    backup_violations.append("No backup retention policy configured")
                                    
                            except Exception:
                                # Backup retention policy API might not be available
                                pass
                            
                            # Check table encryption (important for backup security)
                            sse_description = table.get('SSEDescription', {})
                            if sse_description.get('Status') == 'ENABLED':
                                backup_features.append({
                                    'feature': 'Encryption at Rest',
                                    'kms_key_id': sse_description.get('KMSMasterKeyArn')
                                })
                            else:
                                backup_violations.append("Table encryption not enabled")
                            
                            # Determine compliance
                            if len(backup_violations) > len(backup_features):
                                findings.append({
                                    "region": region_name,
                                    "profile": profile_name or "default",
                                    "resource_type": "dynamodb_global_table",
                                    "resource_id": table.get('TableArn'),
                                    "status": "NON_COMPLIANT",
                                    "risk_level": "MEDIUM",
                                    "recommendation": "Ensure DynamoDB Global Table has proper backup configurations",
                                    "details": {
                                        "table_name": table_name,
                                        "global_table_version": global_table_version,
                                        "replicas_count": len(replicas),
                                        "violation": f"Global Table backup has {len(backup_violations)} configuration issues",
                                        "backup_violations": backup_violations,
                                        "configured_features": backup_features
                                    }
                                })
                            else:
                                findings.append({
                                    "region": region_name,
                                    "profile": profile_name or "default",
                                    "resource_type": "dynamodb_global_table",
                                    "resource_id": table.get('TableArn'),
                                    "status": "COMPLIANT",
                                    "risk_level": "MEDIUM",
                                    "recommendation": "DynamoDB Global Table backup is properly configured",
                                    "details": {
                                        "table_name": table_name,
                                        "global_table_version": global_table_version,
                                        "replicas_count": len(replicas),
                                        "configured_features": backup_features,
                                        "minor_issues": backup_violations if backup_violations else None
                                    }
                                })
                                
                    except Exception as table_error:
                        logger.warning(f"Failed to check table {table_name}: {table_error}")
                        
        except Exception as dynamodb_error:
            logger.warning(f"Failed to check DynamoDB Global Tables: {dynamodb_error}")
        
        # Check RDS Cross-Region Automated Backups
        try:
            rds_client = session.client('rds', region_name=region_name)
            
            # Get all RDS instances
            paginator = rds_client.get_paginator('describe_db_instances')
            
            for page in paginator.paginate():
                for db_instance in page.get('DBInstances', []):
                    db_instance_identifier = db_instance.get('DBInstanceIdentifier')
                    db_instance_arn = db_instance.get('DBInstanceArn')
                    
                    try:
                        backup_violations = []
                        backup_features = []
                        
                        # Check automated backup configuration
                        backup_retention_period = db_instance.get('BackupRetentionPeriod', 0)
                        if backup_retention_period > 0:
                            backup_features.append({
                                'feature': 'Automated Backups',
                                'retention_days': backup_retention_period
                            })
                        else:
                            backup_violations.append("Automated backups not enabled")
                        
                        # Check for cross-region automated backups
                        try:
                            cross_region_response = rds_client.describe_db_instance_automated_backups(
                                DBInstanceIdentifier=db_instance_identifier
                            )
                            
                            automated_backups = cross_region_response.get('DBInstanceAutomatedBackups', [])
                            cross_region_backups = [backup for backup in automated_backups 
                                                  if backup.get('Region') != region_name]
                            
                            if cross_region_backups:
                                backup_features.append({
                                    'feature': 'Cross-Region Automated Backups',
                                    'backup_regions': [b.get('Region') for b in cross_region_backups]
                                })
                            else:
                                backup_violations.append("No cross-region automated backups configured")
                                
                        except Exception as cross_region_error:
                            backup_violations.append(f"Cannot verify cross-region backups: {str(cross_region_error)}")
                        
                        # Check for manual snapshots
                        try:
                            snapshots_response = rds_client.describe_db_snapshots(
                                DBInstanceIdentifier=db_instance_identifier,
                                SnapshotType='manual',
                                MaxRecords=5
                            )
                            
                            manual_snapshots = snapshots_response.get('DBSnapshots', [])
                            if manual_snapshots:
                                backup_features.append({
                                    'feature': 'Manual Snapshots',
                                    'snapshots_count': len(manual_snapshots)
                                })
                                
                        except Exception as snapshots_error:
                            logger.warning(f"Failed to check manual snapshots for {db_instance_identifier}: {snapshots_error}")
                        
                        # Check encryption status
                        storage_encrypted = db_instance.get('StorageEncrypted', False)
                        if storage_encrypted:
                            backup_features.append({
                                'feature': 'Storage Encryption',
                                'kms_key_id': db_instance.get('KmsKeyId')
                            })
                        else:
                            backup_violations.append("Storage encryption not enabled")
                        
                        # Determine compliance
                        critical_violations = len([v for v in backup_violations if 'not enabled' in v.lower()])
                        
                        if critical_violations > 0:
                            findings.append({
                                "region": region_name,
                                "profile": profile_name or "default",
                                "resource_type": "rds_instance",
                                "resource_id": db_instance_arn,
                                "status": "NON_COMPLIANT",
                                "risk_level": "MEDIUM",
                                "recommendation": "Ensure RDS instance has proper backup replication configurations",
                                "details": {
                                    "db_instance_identifier": db_instance_identifier,
                                    "backup_retention_period": backup_retention_period,
                                    "violation": f"RDS backup replication has {len(backup_violations)} configuration issues",
                                    "backup_violations": backup_violations,
                                    "configured_features": backup_features
                                }
                            })
                        else:
                            findings.append({
                                "region": region_name,
                                "profile": profile_name or "default",
                                "resource_type": "rds_instance",
                                "resource_id": db_instance_arn,
                                "status": "COMPLIANT",
                                "risk_level": "MEDIUM",
                                "recommendation": "RDS instance backup replication is properly configured",
                                "details": {
                                    "db_instance_identifier": db_instance_identifier,
                                    "backup_retention_period": backup_retention_period,
                                    "configured_features": backup_features,
                                    "minor_issues": backup_violations if backup_violations else None
                                }
                            })
                            
                    except Exception as instance_error:
                        logger.warning(f"Failed to check RDS instance {db_instance_identifier}: {instance_error}")
                        findings.append({
                            "region": region_name,
                            "profile": profile_name or "default",
                            "resource_type": "rds_instance",
                            "resource_id": db_instance_arn,
                            "status": "ERROR",
                            "risk_level": "MEDIUM",
                            "recommendation": "Unable to check RDS backup replication configuration",
                            "details": {
                                "db_instance_identifier": db_instance_identifier,
                                "error": str(instance_error)
                            }
                        })
                        
        except Exception as rds_error:
            logger.warning(f"Failed to check RDS instances: {rds_error}")
        
        logger.info(f"Completed checking replication_backup_enabled. Found {len(findings)} findings.")
        
    except Exception as e:
        logger.error(f"Failed to check replication_backup_enabled: {e}")
        findings.append({
            "region": region_name,
            "profile": profile_name or "default",
            "resource_type": "replication_backup",
            "resource_id": "unknown",
            "status": "ERROR",
            "risk_level": "MEDIUM",
            "recommendation": "Fix API access issues",
            "details": {
                "error": str(e)
            }
        })
    
    return findings

def replication_backup_enabled(region_name: str, profile_name: str = None) -> Dict[str, Any]:
    """
    Main function wrapper for replication_backup_enabled.
    
    Args:
        region_name (str): AWS region name
        profile_name (str): AWS profile name (optional)
        
    Returns:
        Dict: Results summary
    """
    COMPLIANCE_DATA = load_rule_metadata("replication_backup_enabled")
    
    # TODO: Implement SecurityEngine integration when available
    # from data_security_engine import SecurityEngine
    # engine = SecurityEngine(COMPLIANCE_DATA)
    # return engine.run_check(region_name, profile_name, replication_backup_enabled_check)
    
    # Current implementation
    findings = replication_backup_enabled_check(region_name, profile_name)
    
    # Calculate compliance statistics
    total_findings = len(findings)
    compliant_findings = len([f for f in findings if f['status'] == 'COMPLIANT'])
    non_compliant_findings = len([f for f in findings if f['status'] == 'NON_COMPLIANT'])
    error_findings = len([f for f in findings if f['status'] == 'ERROR'])
    
    return {
        "function_name": "replication_backup_enabled",
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
    """CLI entry point for replication_backup_enabled."""
    # TODO: Implement setup_command_line_interface() when data_security_engine is available
    # from data_security_engine import setup_command_line_interface, save_results, exit_with_status
    # args = setup_command_line_interface()
    # results = replication_backup_enabled(args.region, args.profile)
    # save_results(results, args.output_file)
    # exit_with_status(results)
    
    # Current CLI implementation
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Ensure replication configurations are backed up to prevent data loss and maintain disaster recovery capabilities."
    )
    parser.add_argument("--region", default="us-east-1", help="AWS region")
    parser.add_argument("--profile", help="AWS profile name")
    parser.add_argument("--output", help="Output file for results (JSON format)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        results = replication_backup_enabled(args.region, args.profile)
        
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

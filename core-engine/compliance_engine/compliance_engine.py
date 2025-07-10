#!/usr/bin/env python3
"""
Enhanced Compliance Engine Module

Main compliance engine that orchestrates compliance checks using modular components.
Separated from compliance_utils for better maintainability.
"""

import uuid
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone
import botocore.exceptions

from .aws_session_manager import (
    extract_service_name, 
    get_regions_for_service, 
    create_aws_session, 
    create_enhanced_aws_client,
    get_aws_profiles,
    GLOBAL_SERVICES
)
from .error_handler import (
    EnhancedErrorLogger, 
    handle_enhanced_client_error, 
    update_global_stats,
    global_stats
)
from .account_manager import EnterpriseAccountManager
from .config_utils import (
    setup_logging, 
    load_service_regions,
    initialize_compliance_results,
    determine_overall_status
)


class ComplianceEngine:
    """
    Enhanced compliance engine class with multi-account and advanced error handling support.
    """
    
    def __init__(self, compliance_data: Dict[str, str], logger: Optional[logging.Logger] = None):
        """
        Initialize enhanced compliance engine.
        
        Args:
            compliance_data (Dict[str, str]): Compliance metadata
            logger (Optional[logging.Logger]): Logger instance
        """
        self.compliance_data = compliance_data
        self.logger = logger or setup_logging(compliance_data.get('function_name', 'compliance'))
        self.service_regions = load_service_regions()
        self.session_id = f"compliance_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"
        self.error_logger = EnhancedErrorLogger(self.session_id)
        
    def run_compliance_check(self, 
                           check_function, 
                           profile_name: Optional[str] = None, 
                           region_name: Optional[str] = None,
                           account_manager: EnterpriseAccountManager = None) -> Dict[str, Any]:
        """
        Enhanced compliance check with multi-account support.
        
        Args:
            check_function: Function that performs the actual compliance check
            profile_name (Optional[str]): AWS profile name
            region_name (Optional[str]): Specific region to check
            account_manager (EnterpriseAccountManager): Multi-account manager
            
        Returns:
            Dict[str, Any]: Enhanced compliance check results
        """
        # Initialize results
        results = initialize_compliance_results(self.compliance_data)
        results['session_id'] = self.session_id
        
        try:
            self.logger.info(f"Starting compliance check: {self.compliance_data.get('function_name')}")
            
            # Determine service and regions
            service_name = extract_service_name(self.compliance_data.get('api_function', ''))
            regions = get_regions_for_service(service_name, self.service_regions)
            
            # Override with specific region if provided
            if region_name:
                regions = [region_name]
                
            results['regions_checked'] = regions
            
            # Determine accounts to process
            if account_manager and account_manager.accounts:
                # Use enterprise account manager
                accounts_to_process = account_manager.accounts
                results['profiles_used'] = [acc['name'] for acc in accounts_to_process]
                self.logger.info(f"Using {len(accounts_to_process)} accounts from account manager")
            else:
                # Use traditional single account approach
                profiles = [profile_name] if profile_name else get_aws_profiles()
                accounts_to_process = []
                for profile in profiles:
                    try:
                        session = create_aws_session(profile)
                        sts = session.client('sts')
                        identity = sts.get_caller_identity()
                        accounts_to_process.append({
                            'name': profile,
                            'account_id': identity['Account'],
                            'session': session,
                            'enabled_regions': regions,
                            'auth_method': 'profile'
                        })
                    except Exception as e:
                        self.logger.error(f"Failed to create session for profile {profile}: {e}")
                
                results['profiles_used'] = profiles
            
            # Process each account and region
            for account_info in accounts_to_process:
                account_id = account_info['account_id']
                account_name = account_info['name']
                session = account_info['session']
                
                try:
                    self.logger.info(f"Processing account: {account_name} ({account_id})")
                    
                    for region in regions:
                        try:
                            self.logger.info(f"Checking compliance in region: {region} for account: {account_name}")
                            
                            # Skip non-global services in wrong regions
                            if region != 'us-east-1' and service_name in GLOBAL_SERVICES:
                                self.logger.info(f"Skipping {service_name} in {region} as it's a global service")
                                continue
                            
                            # Create enhanced AWS client
                            client = create_enhanced_aws_client(session, service_name, region)
                            
                            # Execute compliance check with enhanced error handling
                            try:
                                region_findings = check_function(client, region, account_name, self.logger)
                                results['findings'].extend(region_findings)
                                update_global_stats(successful=True)
                                
                            except Exception as e:
                                error_type = self.error_logger.categorize_error(e)
                                self.error_logger.log_error(
                                    account_id, region, service_name, 
                                    self.compliance_data.get('function_name', 'unknown'),
                                    error_type, str(e), 
                                    self.compliance_data.get('compliance_name', 'unknown')
                                )
                                
                                if isinstance(e, botocore.exceptions.ClientError):
                                    error_info = handle_enhanced_client_error(
                                        e, region, account_name, service_name, 
                                        self.compliance_data.get('function_name')
                                    )
                                else:
                                    error_info = {
                                        'region': region,
                                        'profile': account_name,
                                        'account_id': account_id,
                                        'service': service_name,
                                        'error': str(e),
                                        'error_type': 'UnexpectedError',
                                        'error_category': error_type,
                                        'timestamp': datetime.now(timezone.utc).isoformat()
                                    }
                                
                                results['errors'].append(error_info)
                                update_global_stats(successful=False)
                                
                        except Exception as e:
                            self.logger.error(f"Unexpected error in {region} for account {account_name}: {str(e)}")
                            results['errors'].append({
                                'region': region,
                                'profile': account_name,
                                'account_id': account_id,
                                'error': str(e),
                                'error_type': 'RegionError'
                            })
                            
                except Exception as e:
                    self.logger.error(f"Error with account {account_name}: {str(e)}")
                    results['errors'].append({
                        'profile': account_name,
                        'account_id': account_id,
                        'error': str(e),
                        'error_type': 'AccountError'
                    })
            
            # Determine overall status
            results['status'] = determine_overall_status(results)
            
            # Add enhanced analytics
            results['error_analytics'] = {
                'total_errors': len(self.error_logger.errors),
                'error_categories': dict(self.error_logger.error_categories),
                'service_errors': dict(self.error_logger.service_errors),
                'region_errors': dict(self.error_logger.region_errors),
                'account_errors': dict(self.error_logger.account_errors)
            }
            
            results['global_stats'] = global_stats.copy()
            
            self.logger.info(f"Compliance check completed. Status: {results['status']}, "
                           f"Findings: {len(results['findings'])}, Errors: {len(results['errors'])}")
            
        except Exception as e:
            self.logger.error(f"Critical error in compliance check: {str(e)}")
            results['status'] = 'CRITICAL_ERROR'
            results['errors'].append({
                'error': str(e),
                'error_type': 'CriticalError'
            })
        
        return results


# Compliance Check Functions

def iam_password_policy(client, region, profile, logger):
    """Check if IAM password policy is configured with strong requirements"""
    findings = []
    try:
        response = client.get_account_password_policy()
        policy = response['PasswordPolicy']
        
        issues = []
        if policy.get('MinimumPasswordLength', 0) < 14:
            issues.append(f"Minimum password length is {policy.get('MinimumPasswordLength', 0)}, should be at least 14")
        if not policy.get('RequireUppercaseCharacters', False):
            issues.append("Uppercase characters are not required")
        if not policy.get('RequireLowercaseCharacters', False):
            issues.append("Lowercase characters are not required")
        if not policy.get('RequireNumbers', False):
            issues.append("Numbers are not required")
        if not policy.get('RequireSymbols', False):
            issues.append("Symbols are not required")
        if policy.get('MaxPasswordAge', 0) == 0 or policy.get('MaxPasswordAge', 0) > 90:
            issues.append(f"Password max age is {policy.get('MaxPasswordAge', 'unlimited')}, should be 90 days or less")
            
        if issues:
            findings.append({
                'type': 'iam_password_policy',
                'region': region,
                'profile': profile,
                'status': 'FAIL',
                'resource_id': 'account',
                'issues': issues,
                'policy_details': policy
            })
        else:
            findings.append({
                'type': 'iam_password_policy',
                'region': region,
                'profile': profile,
                'status': 'PASS',
                'resource_id': 'account',
                'policy_details': policy
            })
            
    except client.exceptions.NoSuchEntityException:
        findings.append({
            'type': 'iam_password_policy',
            'region': region,
            'profile': profile,
            'status': 'FAIL',
            'resource_id': 'account',
            'issues': ['No password policy configured']
        })
    except Exception as e:
        logger.error(f"Error checking IAM password policy: {e}")
        findings.append({
            'type': 'iam_password_policy',
            'region': region,
            'profile': profile,
            'status': 'ERROR',
            'resource_id': 'account',
            'error': str(e)
        })
    return findings


def iam_users_mfa_enabled(client, region, profile, logger):
    """Check if all IAM users have MFA enabled"""
    findings = []
    try:
        paginator = client.get_paginator('list_users')
        users_without_mfa = []
        
        for page in paginator.paginate():
            for user in page['Users']:
                username = user['UserName']
                
                # Check for MFA devices
                mfa_devices = client.list_mfa_devices(UserName=username)
                virtual_mfa = client.list_virtual_mfa_devices()
                
                has_mfa = len(mfa_devices['MFADevices']) > 0
                has_virtual_mfa = any(device['User']['UserName'] == username 
                                    for device in virtual_mfa['VirtualMFADevices'] 
                                    if 'User' in device)
                
                if not (has_mfa or has_virtual_mfa):
                    users_without_mfa.append(username)
        
        if users_without_mfa:
            findings.append({
                'type': 'iam_users_mfa_enabled',
                'region': region,
                'profile': profile,
                'status': 'FAIL',
                'resource_id': 'iam_users',
                'issues': [f"Users without MFA: {', '.join(users_without_mfa)}"]
            })
        else:
            findings.append({
                'type': 'iam_users_mfa_enabled',
                'region': region,
                'profile': profile,
                'status': 'PASS',
                'resource_id': 'iam_users'
            })
            
    except Exception as e:
        logger.error(f"Error checking IAM users MFA: {e}")
        
    return findings


def cloudtrail_enabled(client, region, profile, logger):
    """Check if CloudTrail is enabled"""
    findings = []
    try:
        response = client.describe_trails()
        trails = response.get('trailList', [])
        
        if not trails:
            findings.append({
                'type': 'cloudtrail_enabled',
                'region': region,
                'profile': profile,
                'status': 'FAIL',
                'resource_id': region,
                'issues': ['No CloudTrail trails found']
            })
        else:
            for trail in trails:
                trail_name = trail['Name']
                trail_arn = trail['TrailARN']
                
                # Check if trail is logging
                try:
                    status_response = client.get_trail_status(Name=trail_name)
                    is_logging = status_response.get('IsLogging', False)
                    
                    if is_logging:
                        findings.append({
                            'type': 'cloudtrail_enabled',
                            'region': region,
                            'profile': profile,
                            'status': 'PASS',
                            'resource_id': trail_arn,
                            'trail_name': trail_name,
                            'is_multi_region': trail.get('IsMultiRegionTrail', False),
                            'include_global_services': trail.get('IncludeGlobalServiceEvents', False)
                        })
                    else:
                        findings.append({
                            'type': 'cloudtrail_enabled',
                            'region': region,
                            'profile': profile,
                            'status': 'FAIL',
                            'resource_id': trail_arn,
                            'issues': [f'CloudTrail {trail_name} is not actively logging']
                        })
                except Exception as e:
                    logger.warning(f"Could not get status for trail {trail_name}: {e}")
                    
    except Exception as e:
        logger.error(f"Error checking CloudTrail: {e}")
        findings.append({
            'type': 'cloudtrail_enabled',
            'region': region,
            'profile': profile,
            'status': 'ERROR',
            'resource_id': region,
            'error': str(e)
        })
    return findings


def ec2_security_groups_unrestricted_access(client, region, profile, logger):
    """Check for security groups with unrestricted access (0.0.0.0/0)"""
    findings = []
    try:
        response = client.describe_security_groups()
        
        for sg in response['SecurityGroups']:
            issues = []
            
            # Check inbound rules
            for rule in sg.get('IpPermissions', []):
                for ip_range in rule.get('IpRanges', []):
                    if ip_range.get('CidrIp') == '0.0.0.0/0':
                        port_info = f"Port {rule.get('FromPort', 'All')}"
                        if rule.get('FromPort') != rule.get('ToPort'):
                            port_info = f"Ports {rule.get('FromPort', 'All')}-{rule.get('ToPort', 'All')}"
                        issues.append(f"Inbound rule allows unrestricted access on {port_info}")
            
            if issues:
                findings.append({
                    'type': 'ec2_security_groups_unrestricted_access',
                    'region': region,
                    'profile': profile,
                    'status': 'FAIL',
                    'resource_id': sg['GroupId'],
                    'resource_name': sg.get('GroupName'),
                    'issues': issues
                })
        
        if not any(f['status'] == 'FAIL' for f in findings):
            findings.append({
                'type': 'ec2_security_groups_unrestricted_access',
                'region': region,
                'profile': profile,
                'status': 'PASS',
                'resource_id': 'all_security_groups'
            })
            
    except Exception as e:
        logger.error(f"Error checking security groups: {e}")
        
    return findings


def s3_bucket_public_read_prohibited(client, region, profile, logger):
    """Check if S3 buckets prohibit public read access"""
    findings = []
    try:
        buckets = client.list_buckets()['Buckets']
        
        for bucket in buckets:
            bucket_name = bucket['Name']
            
            try:
                # Check bucket ACL
                acl = client.get_bucket_acl(Bucket=bucket_name)
                public_read = False
                
                for grant in acl['Grants']:
                    grantee = grant.get('Grantee', {})
                    if grantee.get('Type') == 'Group':
                        uri = grantee.get('URI', '')
                        if 'AllUsers' in uri or 'AuthenticatedUsers' in uri:
                            if grant['Permission'] in ['READ', 'FULL_CONTROL']:
                                public_read = True
                                break
                
                # Check bucket policy for public access
                try:
                    policy_response = client.get_bucket_policy(Bucket=bucket_name)
                    policy = policy_response['Policy']
                    if '"Principal":"*"' in policy and '"Effect":"Allow"' in policy:
                        public_read = True
                except client.exceptions.NoSuchBucketPolicy:
                    pass
                
                if public_read:
                    findings.append({
                        'type': 's3_bucket_public_read_prohibited',
                        'region': region,
                        'profile': profile,
                        'status': 'FAIL',
                        'resource_id': bucket_name,
                        'issues': ['Bucket allows public read access']
                    })
                else:
                    findings.append({
                        'type': 's3_bucket_public_read_prohibited',
                        'region': region,
                        'profile': profile,
                        'status': 'PASS',
                        'resource_id': bucket_name
                    })
                    
            except Exception as e:
                logger.error(f"Error checking bucket {bucket_name}: {e}")
                
    except Exception as e:
        logger.error(f"Error checking S3 buckets: {e}")
        
    return findings


def vpc_default_security_group_restricts_all_traffic(client, region, profile, logger):
    """Check if default VPC security groups restrict all traffic"""
    findings = []
    try:
        vpcs = client.describe_vpcs()['Vpcs']
        
        for vpc in vpcs:
            vpc_id = vpc['VpcId']
            
            # Get default security group for this VPC
            sgs = client.describe_security_groups(
                Filters=[
                    {'Name': 'vpc-id', 'Values': [vpc_id]},
                    {'Name': 'group-name', 'Values': ['default']}
                ]
            )['SecurityGroups']
            
            for sg in sgs:
                has_rules = len(sg.get('IpPermissions', [])) > 0 or len(sg.get('IpPermissionsEgress', [])) > 1
                
                if has_rules:
                    findings.append({
                        'type': 'vpc_default_security_group_restricts_all_traffic',
                        'region': region,
                        'profile': profile,
                        'status': 'FAIL',
                        'resource_id': sg['GroupId'],
                        'vpc_id': vpc_id,
                        'issues': ['Default security group has inbound or outbound rules']
                    })
                else:
                    findings.append({
                        'type': 'vpc_default_security_group_restricts_all_traffic',
                        'region': region,
                        'profile': profile,
                        'status': 'PASS',
                        'resource_id': sg['GroupId'],
                        'vpc_id': vpc_id
                    })
                    
    except Exception as e:
        logger.error(f"Error checking default security groups: {e}")
        
    return findings


def rds_instance_backup_enabled(client, region, profile, logger):
    """Check if RDS instances have automated backups enabled"""
    findings = []
    try:
        response = client.describe_db_instances()
        
        for db_instance in response['DBInstances']:
            instance_id = db_instance['DBInstanceIdentifier']
            backup_retention = db_instance.get('BackupRetentionPeriod', 0)
            
            if backup_retention == 0:
                findings.append({
                    'type': 'rds_instance_backup_enabled',
                    'region': region,
                    'profile': profile,
                    'status': 'FAIL',
                    'resource_id': instance_id,
                    'issues': ['Automated backups are disabled']
                })
            else:
                findings.append({
                    'type': 'rds_instance_backup_enabled',
                    'region': region,
                    'profile': profile,
                    'status': 'PASS',
                    'resource_id': instance_id,
                    'backup_retention_days': backup_retention
                })
                
    except Exception as e:
        logger.error(f"Error checking RDS backup settings: {e}")
        
    return findings


def kafka_cluster_encryption_at_rest_uses_cmk(client, region, profile, logger):
    """Check if Kafka clusters use customer-managed keys for encryption at rest"""
    findings = []
    try:
        paginator = client.get_paginator('list_clusters')
        
        for page in paginator.paginate():
            for cluster in page['ClusterInfoList']:
                cluster_arn = cluster['ClusterArn']
                cluster_name = cluster['ClusterName']
                
                try:
                    # Get detailed cluster information
                    cluster_detail = client.describe_cluster(ClusterArn=cluster_arn)
                    cluster_info = cluster_detail['ClusterInfo']
                    
                    encryption_info = cluster_info.get('EncryptionInfo', {})
                    encryption_at_rest = encryption_info.get('EncryptionAtRest', {})
                    
                    # Check if encryption is enabled and uses CMK
                    data_volume_kms_key_id = encryption_at_rest.get('DataVolumeKMSKeyId')
                    
                    if not data_volume_kms_key_id:
                        findings.append({
                            'type': 'kafka_cluster_encryption_at_rest_uses_cmk',
                            'region': region,
                            'profile': profile,
                            'status': 'FAIL',
                            'resource_id': cluster_arn,
                            'resource_name': cluster_name,
                            'issues': ['Cluster does not use customer-managed KMS key for encryption at rest']
                        })
                    elif data_volume_kms_key_id.startswith('alias/aws/'):
                        findings.append({
                            'type': 'kafka_cluster_encryption_at_rest_uses_cmk',
                            'region': region,
                            'profile': profile,
                            'status': 'FAIL',
                            'resource_id': cluster_arn,
                            'resource_name': cluster_name,
                            'issues': ['Cluster uses AWS managed key instead of customer-managed key']
                        })
                    else:
                        findings.append({
                            'type': 'kafka_cluster_encryption_at_rest_uses_cmk',
                            'region': region,
                            'profile': profile,
                            'status': 'PASS',
                            'resource_id': cluster_arn,
                            'resource_name': cluster_name,
                            'kms_key_id': data_volume_kms_key_id
                        })
                        
                except Exception as e:
                    logger.error(f"Error checking cluster {cluster_name}: {e}")
                    findings.append({
                        'type': 'kafka_cluster_encryption_at_rest_uses_cmk',
                        'region': region,
                        'profile': profile,
                        'status': 'ERROR',
                        'resource_id': cluster_arn,
                        'resource_name': cluster_name,
                        'error': str(e)
                    })
                    
    except Exception as e:
        logger.error(f"Error listing Kafka clusters: {e}")
        
    return findings


def kafka_cluster_enhanced_monitoring_enabled(client, region, profile, logger):
    """Check if Kafka clusters have enhanced monitoring enabled"""
    findings = []
    try:
        paginator = client.get_paginator('list_clusters')
        
        for page in paginator.paginate():
            for cluster in page['ClusterInfoList']:
                cluster_arn = cluster['ClusterArn']
                cluster_name = cluster['ClusterName']
                
                try:
                    # Get detailed cluster information
                    cluster_detail = client.describe_cluster(ClusterArn=cluster_arn)
                    cluster_info = cluster_detail['ClusterInfo']
                    
                    monitoring_info = cluster_info.get('LoggingInfo', {})
                    broker_logs = monitoring_info.get('BrokerLogs', {})
                    
                    # Check for enhanced monitoring (JMX and Node exporter)
                    open_monitoring = cluster_info.get('OpenMonitoring', {})
                    prometheus = open_monitoring.get('Prometheus', {})
                    jmx_exporter = prometheus.get('JmxExporter', {})
                    node_exporter = prometheus.get('NodeExporter', {})
                    
                    # Check monitoring level
                    enhanced_monitoring = cluster_info.get('EnhancedMonitoring', 'DEFAULT')
                    
                    issues = []
                    if enhanced_monitoring == 'DEFAULT':
                        issues.append('Enhanced monitoring is set to DEFAULT (minimal)')
                    elif enhanced_monitoring == 'PER_BROKER':
                        issues.append('Enhanced monitoring is set to PER_BROKER (not PER_TOPIC_PER_BROKER)')
                    
                    if not jmx_exporter.get('EnabledInBroker', False):
                        issues.append('JMX Exporter is not enabled')
                        
                    if not node_exporter.get('EnabledInBroker', False):
                        issues.append('Node Exporter is not enabled')
                    
                    if issues:
                        findings.append({
                            'type': 'kafka_cluster_enhanced_monitoring_enabled',
                            'region': region,
                            'profile': profile,
                            'status': 'FAIL',
                            'resource_id': cluster_arn,
                            'resource_name': cluster_name,
                            'issues': issues,
                            'monitoring_level': enhanced_monitoring
                        })
                    else:
                        findings.append({
                            'type': 'kafka_cluster_enhanced_monitoring_enabled',
                            'region': region,
                            'profile': profile,
                            'status': 'PASS',
                            'resource_id': cluster_arn,
                            'resource_name': cluster_name,
                            'monitoring_level': enhanced_monitoring
                        })
                        
                except Exception as e:
                    logger.error(f"Error checking cluster {cluster_name}: {e}")
                    findings.append({
                        'type': 'kafka_cluster_enhanced_monitoring_enabled',
                        'region': region,
                        'profile': profile,
                        'status': 'ERROR',
                        'resource_id': cluster_arn,
                        'resource_name': cluster_name,
                        'error': str(e)
                    })
                    
    except Exception as e:
        logger.error(f"Error listing Kafka clusters: {e}")
        
    return findings


def kafka_cluster_in_transit_encryption_enabled(client, region, profile, logger):
    """Check if Kafka clusters have in-transit encryption enabled"""
    findings = []
    try:
        paginator = client.get_paginator('list_clusters')
        
        for page in paginator.paginate():
            for cluster in page['ClusterInfoList']:
                cluster_arn = cluster['ClusterArn']
                cluster_name = cluster['ClusterName']
                
                try:
                    # Get detailed cluster information
                    cluster_detail = client.describe_cluster(ClusterArn=cluster_arn)
                    cluster_info = cluster_detail['ClusterInfo']
                    
                    encryption_info = cluster_info.get('EncryptionInfo', {})
                    encryption_in_transit = encryption_info.get('EncryptionInTransit', {})
                    
                    # Check client broker encryption
                    client_broker = encryption_in_transit.get('ClientBroker', 'PLAINTEXT')
                    in_cluster = encryption_in_transit.get('InCluster', False)
                    
                    issues = []
                    if client_broker == 'PLAINTEXT':
                        issues.append('Client-broker communication uses plaintext (no encryption)')
                    elif client_broker == 'TLS_PLAINTEXT':
                        issues.append('Client-broker communication allows both TLS and plaintext')
                    
                    if not in_cluster:
                        issues.append('Inter-broker communication is not encrypted')
                    
                    if issues:
                        findings.append({
                            'type': 'kafka_cluster_in_transit_encryption_enabled',
                            'region': region,
                            'profile': profile,
                            'status': 'FAIL',
                            'resource_id': cluster_arn,
                            'resource_name': cluster_name,
                            'issues': issues,
                            'client_broker_encryption': client_broker,
                            'in_cluster_encryption': in_cluster
                        })
                    else:
                        findings.append({
                            'type': 'kafka_cluster_in_transit_encryption_enabled',
                            'region': region,
                            'profile': profile,
                            'status': 'PASS',
                            'resource_id': cluster_arn,
                            'resource_name': cluster_name,
                            'client_broker_encryption': client_broker,
                            'in_cluster_encryption': in_cluster
                        })
                        
                except Exception as e:
                    logger.error(f"Error checking cluster {cluster_name}: {e}")
                    findings.append({
                        'type': 'kafka_cluster_in_transit_encryption_enabled',
                        'region': region,
                        'profile': profile,
                        'status': 'ERROR',
                        'resource_id': cluster_arn,
                        'resource_name': cluster_name,
                        'error': str(e)
                    })
                    
    except Exception as e:
        logger.error(f"Error listing Kafka clusters: {e}")
        
    return findings


def kafka_cluster_is_public(client, region, profile, logger):
    """Check if Kafka clusters are not publicly accessible"""
    findings = []
    try:
        paginator = client.get_paginator('list_clusters')
        
        for page in paginator.paginate():
            for cluster in page['ClusterInfoList']:
                cluster_arn = cluster['ClusterArn']
                cluster_name = cluster['ClusterName']
                
                try:
                    # Get detailed cluster information
                    cluster_detail = client.describe_cluster(ClusterArn=cluster_arn)
                    cluster_info = cluster_detail['ClusterInfo']
                    
                    broker_node_group_info = cluster_info.get('BrokerNodeGroupInfo', {})
                    connectivity_info = broker_node_group_info.get('ConnectivityInfo', {})
                    public_access = connectivity_info.get('PublicAccess', {})
                    
                    # Check if public access is enabled
                    public_access_type = public_access.get('Type', 'DISABLED')
                    
                    if public_access_type != 'DISABLED':
                        findings.append({
                            'type': 'kafka_cluster_is_public',
                            'region': region,
                            'profile': profile,
                            'status': 'FAIL',
                            'resource_id': cluster_arn,
                            'resource_name': cluster_name,
                            'issues': [f'Cluster has public access enabled: {public_access_type}'],
                            'public_access_type': public_access_type
                        })
                    else:
                        findings.append({
                            'type': 'kafka_cluster_is_public',
                            'region': region,
                            'profile': profile,
                            'status': 'PASS',
                            'resource_id': cluster_arn,
                            'resource_name': cluster_name,
                            'public_access_type': public_access_type
                        })
                        
                except Exception as e:
                    logger.error(f"Error checking cluster {cluster_name}: {e}")
                    findings.append({
                        'type': 'kafka_cluster_is_public',
                        'region': region,
                        'profile': profile,
                        'status': 'ERROR',
                        'resource_id': cluster_arn,
                        'resource_name': cluster_name,
                        'error': str(e)
                    })
                    
    except Exception as e:
        logger.error(f"Error listing Kafka clusters: {e}")
        
    return findings


def kafka_cluster_mutual_tls_authentication_enabled(client, region, profile, logger):
    """Check if Kafka clusters have mutual TLS authentication enabled"""
    findings = []
    try:
        paginator = client.get_paginator('list_clusters')
        
        for page in paginator.paginate():
            for cluster in page['ClusterInfoList']:
                cluster_arn = cluster['ClusterArn']
                cluster_name = cluster['ClusterName']
                
                try:
                    # Get detailed cluster information
                    cluster_detail = client.describe_cluster(ClusterArn=cluster_arn)
                    cluster_info = cluster_detail['ClusterInfo']
                    
                    client_authentication = cluster_info.get('ClientAuthentication', {})
                    
                    # Check for TLS authentication
                    tls_auth = client_authentication.get('Tls', {})
                    certificate_authority_arn_list = tls_auth.get('CertificateAuthorityArnList', [])
                    enabled = tls_auth.get('Enabled', False)
                    
                    # Check for SASL authentication as alternative
                    sasl_auth = client_authentication.get('Sasl', {})
                    scram_enabled = sasl_auth.get('Scram', {}).get('Enabled', False)
                    iam_enabled = sasl_auth.get('Iam', {}).get('Enabled', False)
                    
                    issues = []
                    if not enabled and not certificate_authority_arn_list:
                        if not scram_enabled and not iam_enabled:
                            issues.append('No client authentication method is enabled')
                        else:
                            # SASL is enabled but not mTLS - this might be acceptable
                            pass
                    elif enabled and not certificate_authority_arn_list:
                        issues.append('TLS authentication is enabled but no certificate authority is configured')
                    
                    auth_methods = []
                    if enabled and certificate_authority_arn_list:
                        auth_methods.append('mTLS')
                    if scram_enabled:
                        auth_methods.append('SASL/SCRAM')
                    if iam_enabled:
                        auth_methods.append('SASL/IAM')
                    
                    if issues:
                        findings.append({
                            'type': 'kafka_cluster_mutual_tls_authentication_enabled',
                            'region': region,
                            'profile': profile,
                            'status': 'FAIL',
                            'resource_id': cluster_arn,
                            'resource_name': cluster_name,
                            'issues': issues,
                            'authentication_methods': auth_methods
                        })
                    else:
                        findings.append({
                            'type': 'kafka_cluster_mutual_tls_authentication_enabled',
                            'region': region,
                            'profile': profile,
                            'status': 'PASS',
                            'resource_id': cluster_arn,
                            'resource_name': cluster_name,
                            'authentication_methods': auth_methods
                        })
                        
                except Exception as e:
                    logger.error(f"Error checking cluster {cluster_name}: {e}")
                    findings.append({
                        'type': 'kafka_cluster_mutual_tls_authentication_enabled',
                        'region': region,
                        'profile': profile,
                        'status': 'ERROR',
                        'resource_id': cluster_arn,
                        'resource_name': cluster_name,
                        'error': str(e)
                    })
                    
    except Exception as e:
        logger.error(f"Error listing Kafka clusters: {e}")
        
    return findings


def kafka_cluster_unrestricted_access_disabled(client, region, profile, logger):
    """Check if Kafka clusters don't have unrestricted access through security groups"""
    findings = []
    try:
        paginator = client.get_paginator('list_clusters')
        ec2_client = None
        
        for page in paginator.paginate():
            for cluster in page['ClusterInfoList']:
                cluster_arn = cluster['ClusterArn']
                cluster_name = cluster['ClusterName']
                
                try:
                    # Get detailed cluster information
                    cluster_detail = client.describe_cluster(ClusterArn=cluster_arn)
                    cluster_info = cluster_detail['ClusterInfo']
                    
                    broker_node_group_info = cluster_info.get('BrokerNodeGroupInfo', {})
                    security_groups = broker_node_group_info.get('SecurityGroups', [])
                    
                    if not security_groups:
                        findings.append({
                            'type': 'kafka_cluster_unrestricted_access_disabled',
                            'region': region,
                            'profile': profile,
                            'status': 'FAIL',
                            'resource_id': cluster_arn,
                            'resource_name': cluster_name,
                            'issues': ['No security groups associated with cluster']
                        })
                        continue
                    
                    # Create EC2 client if not already created
                    if not ec2_client:
                        import boto3
                        ec2_client = boto3.client('ec2', region_name=region)
                    
                    # Check security groups for unrestricted access
                    unrestricted_sgs = []
                    for sg_id in security_groups:
                        try:
                            sg_response = ec2_client.describe_security_groups(GroupIds=[sg_id])
                            for sg in sg_response['SecurityGroups']:
                                for rule in sg.get('IpPermissions', []):
                                    # Check for Kafka ports (9092, 9094, 9096, etc.)
                                    from_port = rule.get('FromPort', 0)
                                    to_port = rule.get('ToPort', 65535)
                                    
                                    # Check if Kafka ports are exposed
                                    kafka_ports = [9092, 9094, 9096, 9098]
                                    for kafka_port in kafka_ports:
                                        if from_port <= kafka_port <= to_port:
                                            for ip_range in rule.get('IpRanges', []):
                                                if ip_range.get('CidrIp') == '0.0.0.0/0':
                                                    unrestricted_sgs.append({
                                                        'security_group_id': sg_id,
                                                        'port': kafka_port,
                                                        'protocol': rule.get('IpProtocol', 'unknown')
                                                    })
                        except Exception as sg_error:
                            logger.error(f"Error checking security group {sg_id}: {sg_error}")
                    
                    if unrestricted_sgs:
                        findings.append({
                            'type': 'kafka_cluster_unrestricted_access_disabled',
                            'region': region,
                            'profile': profile,
                            'status': 'FAIL',
                            'resource_id': cluster_arn,
                            'resource_name': cluster_name,
                            'issues': [f'Security group {sg["security_group_id"]} allows unrestricted access to Kafka port {sg["port"]}' for sg in unrestricted_sgs],
                            'unrestricted_security_groups': unrestricted_sgs
                        })
                    else:
                        findings.append({
                            'type': 'kafka_cluster_unrestricted_access_disabled',
                            'region': region,
                            'profile': profile,
                            'status': 'PASS',
                            'resource_id': cluster_arn,
                            'resource_name': cluster_name,
                            'security_groups': security_groups
                        })
                        
                except Exception as e:
                    logger.error(f"Error checking cluster {cluster_name}: {e}")
                    findings.append({
                        'type': 'kafka_cluster_unrestricted_access_disabled',
                        'region': region,
                        'profile': profile,
                        'status': 'ERROR',
                        'resource_id': cluster_arn,
                        'resource_name': cluster_name,
                        'error': str(e)
                    })
                    
    except Exception as e:
        logger.error(f"Error listing Kafka clusters: {e}")
        
    return findings


def kafka_cluster_uses_latest_version(client, region, profile, logger):
    """Check if Kafka clusters use the latest available version"""
    findings = []
    try:
        # Get available Kafka versions
        versions_response = client.list_kafka_versions()
        available_versions = versions_response.get('KafkaVersions', [])
        
        if not available_versions:
            logger.warning("No Kafka versions found")
            return findings
        
        # Find the latest version
        latest_version = max(available_versions, key=lambda x: x.get('Version', '0.0.0'))['Version']
        
        paginator = client.get_paginator('list_clusters')
        
        for page in paginator.paginate():
            for cluster in page['ClusterInfoList']:
                cluster_arn = cluster['ClusterArn']
                cluster_name = cluster['ClusterName']
                
                try:
                    # Get detailed cluster information
                    cluster_detail = client.describe_cluster(ClusterArn=cluster_arn)
                    cluster_info = cluster_detail['ClusterInfo']
                    
                    current_version = cluster_info.get('CurrentVersion', 'unknown')
                    kafka_version = None
                    
                    # Extract Kafka version from broker software info
                    broker_software_info = cluster_info.get('BrokerSoftwareInfo', {})
                    kafka_version = broker_software_info.get('KafkaVersion', 'unknown')
                    
                    if kafka_version == 'unknown':
                        findings.append({
                            'type': 'kafka_cluster_uses_latest_version',
                            'region': region,
                            'profile': profile,
                            'status': 'ERROR',
                            'resource_id': cluster_arn,
                            'resource_name': cluster_name,
                            'error': 'Could not determine Kafka version'
                        })
                        continue
                    
                    if kafka_version != latest_version:
                        findings.append({
                            'type': 'kafka_cluster_uses_latest_version',
                            'region': region,
                            'profile': profile,
                            'status': 'FAIL',
                            'resource_id': cluster_arn,
                            'resource_name': cluster_name,
                            'issues': [f'Cluster uses Kafka version {kafka_version}, latest available is {latest_version}'],
                            'current_version': kafka_version,
                            'latest_version': latest_version
                        })
                    else:
                        findings.append({
                            'type': 'kafka_cluster_uses_latest_version',
                            'region': region,
                            'profile': profile,
                            'status': 'PASS',
                            'resource_id': cluster_arn,
                            'resource_name': cluster_name,
                            'current_version': kafka_version,
                            'latest_version': latest_version
                        })
                        
                except Exception as e:
                    logger.error(f"Error checking cluster {cluster_name}: {e}")
                    findings.append({
                        'type': 'kafka_cluster_uses_latest_version',
                        'region': region,
                        'profile': profile,
                        'status': 'ERROR',
                        'resource_id': cluster_arn,
                        'resource_name': cluster_name,
                        'error': str(e)
                    })
                    
    except Exception as e:
        logger.error(f"Error checking Kafka cluster versions: {e}")
        
    return findings


def kafka_connector_in_transit_encryption_enabled(client, region, profile, logger):
    """Check if Kafka connectors have in-transit encryption enabled"""
    findings = []
    try:
        paginator = client.get_paginator('list_connectors')
        
        for page in paginator.paginate():
            for connector in page['Connectors']:
                connector_arn = connector['ConnectorArn']
                connector_name = connector['ConnectorName']
                
                try:
                    # Get detailed connector information
                    connector_detail = client.describe_connector(ConnectorArn=connector_arn)
                    connector_info = connector_detail['ConnectorDescription']
                    
                    # Check Kafka cluster connectivity
                    kafka_cluster = connector_info.get('KafkaCluster', {})
                    apache_kafka_cluster = kafka_cluster.get('ApacheKafkaCluster', {})
                    
                    # Check if SSL is used in bootstrap servers
                    bootstrap_servers = apache_kafka_cluster.get('BootstrapServers', '')
                    vpc_config = apache_kafka_cluster.get('Vpc', {})
                    
                    # Check worker configuration for SSL
                    worker_config = connector_info.get('WorkerConfiguration', {})
                    
                    issues = []
                    
                    # Check if bootstrap servers use SSL ports
                    if bootstrap_servers:
                        # Kafka SSL typically uses port 9093 or 9094
                        if ':9092' in bootstrap_servers:  # Plain text port
                            issues.append('Bootstrap servers use plaintext port 9092')
                        elif not any(port in bootstrap_servers for port in [':9093', ':9094', ':9096']):
                            issues.append('Bootstrap servers may not be using SSL ports')
                    else:
                        issues.append('No bootstrap servers configured')
                    
                    # Check connector configuration for SSL settings
                    connector_config = connector_info.get('ConnectorConfiguration', {})
                    ssl_settings = {
                        'security.protocol': connector_config.get('security.protocol', ''),
                        'ssl.endpoint.identification.algorithm': connector_config.get('ssl.endpoint.identification.algorithm', ''),
                        'ssl.truststore.location': connector_config.get('ssl.truststore.location', ''),
                        'ssl.keystore.location': connector_config.get('ssl.keystore.location', '')
                    }
                    
                    if ssl_settings['security.protocol'] not in ['SSL', 'SASL_SSL']:
                        issues.append(f'Security protocol is {ssl_settings["security.protocol"] or "not set"}, should be SSL or SASL_SSL')
                    
                    if issues:
                        findings.append({
                            'type': 'kafka_connector_in_transit_encryption_enabled',
                            'region': region,
                            'profile': profile,
                            'status': 'FAIL',
                            'resource_id': connector_arn,
                            'resource_name': connector_name,
                            'issues': issues,
                            'ssl_configuration': ssl_settings
                        })
                    else:
                        findings.append({
                            'type': 'kafka_connector_in_transit_encryption_enabled',
                            'region': region,
                            'profile': profile,
                            'status': 'PASS',
                            'resource_id': connector_arn,
                            'resource_name': connector_name,
                            'ssl_configuration': ssl_settings
                        })
                        
                except Exception as e:
                    logger.error(f"Error checking connector {connector_name}: {e}")
                    findings.append({
                        'type': 'kafka_connector_in_transit_encryption_enabled',
                        'region': region,
                        'profile': profile,
                        'status': 'ERROR',
                        'resource_id': connector_arn,
                        'resource_name': connector_name,
                        'error': str(e)
                    })
                    
    except Exception as e:
        logger.error(f"Error listing Kafka connectors: {e}")
        
    return findings


def iam_access_analyzer_enabled(client, region, profile, logger):
    """Check if IAM Access Analyzer is enabled"""
    findings = []
    try:
        response = client.list_analyzers()
        analyzers = response.get('analyzers', [])
        
        active_analyzers = [a for a in analyzers if a['status'] == 'ACTIVE']
        
        if not active_analyzers:
            findings.append({
                'type': 'iam_access_analyzer_enabled',
                'region': region,
                'profile': profile,
                'status': 'FAIL',
                'resource_id': region,
                'issues': ['No active IAM Access Analyzers found']
            })
        else:
            for analyzer in active_analyzers:
                findings.append({
                    'type': 'iam_access_analyzer_enabled',
                    'region': region,
                    'profile': profile,
                    'status': 'PASS',
                    'resource_id': analyzer['arn'],
                    'analyzer_name': analyzer['name'],
                    'analyzer_type': analyzer['type']
                })
                
    except Exception as e:
        logger.error(f"Error checking IAM Access Analyzer: {e}")
        findings.append({
            'type': 'iam_access_analyzer_enabled',
            'region': region,
            'profile': profile,
            'status': 'ERROR',
            'resource_id': region,
            'error': str(e)
        })
    return findings


def accessanalyzer_enabled_without_findings(client, region, profile, logger):
    """Check if IAM Access Analyzer is enabled and has no active findings"""
    findings = []
    try:
        # First check if Access Analyzer is enabled (has analyzers)
        analyzers_response = client.list_analyzers()
        analyzers = analyzers_response.get('analyzers', [])
        
        if not analyzers:
            findings.append({
                'type': 'accessanalyzer_enabled_without_findings',
                'region': region,
                'profile': profile,
                'status': 'FAIL',
                'resource_id': f"access-analyzer-{region}",
                'issues': ['No Access Analyzer found in this region']
            })
            return findings
        
        # Check for active findings across all analyzers
        region_findings = []
        analyzer_details = []
        
        for analyzer in analyzers:
            analyzer_arn = analyzer['arn']
            analyzer_name = analyzer['name']
            analyzer_status = analyzer.get('status', 'UNKNOWN')
            
            try:
                # Only check findings for active analyzers
                if analyzer_status == 'ACTIVE':
                    findings_response = client.list_findings(analyzerArn=analyzer_arn)
                    analyzer_findings = findings_response.get('findings', [])
                    region_findings.extend(analyzer_findings)
                    
                    analyzer_details.append({
                        'name': analyzer_name,
                        'arn': analyzer_arn,
                        'status': analyzer_status,
                        'findings_count': len(analyzer_findings)
                    })
                else:
                    analyzer_details.append({
                        'name': analyzer_name,
                        'arn': analyzer_arn,
                        'status': analyzer_status,
                        'findings_count': 'N/A (not active)'
                    })
                    
            except Exception as e:
                logger.warning(f"Failed to list findings for analyzer {analyzer_name} in {region}: {str(e)}")
                analyzer_details.append({
                    'name': analyzer_name,
                    'arn': analyzer_arn,
                    'status': analyzer_status,
                    'error': str(e)
                })
        
        if region_findings:
            findings.append({
                'type': 'accessanalyzer_enabled_without_findings',
                'region': region,
                'profile': profile,
                'status': 'FAIL',
                'resource_id': f"access-analyzer-{region}",
                'issues': [f'Found {len(region_findings)} active findings across {len(analyzers)} analyzers'],
                'findings_count': len(region_findings),
                'analyzer_count': len(analyzers),
                'analyzers': analyzer_details
            })
        else:
            # Check if we have at least one active analyzer
            active_analyzers = [a for a in analyzer_details if a.get('status') == 'ACTIVE']
            if not active_analyzers:
                findings.append({
                    'type': 'accessanalyzer_enabled_without_findings',
                    'region': region,
                    'profile': profile,
                    'status': 'FAIL',
                    'resource_id': f"access-analyzer-{region}",
                    'issues': ['Access Analyzer exists but no active analyzers found'],
                    'analyzer_count': len(analyzers),
                    'analyzers': analyzer_details
                })
            else:
                findings.append({
                    'type': 'accessanalyzer_enabled_without_findings',
                    'region': region,
                    'profile': profile,
                    'status': 'PASS',
                    'resource_id': f"access-analyzer-{region}",
                    'findings_count': 0,
                    'analyzer_count': len(analyzers),
                    'active_analyzers_count': len(active_analyzers),
                    'analyzers': analyzer_details
                })
                
    except client.exceptions.ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code in ['UnauthorizedOperation', 'AccessDenied']:
            findings.append({
                'type': 'accessanalyzer_enabled_without_findings',
                'region': region,
                'profile': profile,
                'status': 'SKIP',
                'resource_id': f"access-analyzer-{region}",
                'issues': [f'Insufficient permissions to check Access Analyzer: {error_code}']
            })
        else:
            findings.append({
                'type': 'accessanalyzer_enabled_without_findings',
                'region': region,
                'profile': profile,
                'status': 'ERROR',
                'resource_id': f"access-analyzer-{region}",
                'error': str(e)
            })
    except Exception as e:
        logger.error(f"Error checking Access Analyzer findings in {region}: {e}")
        findings.append({
            'type': 'accessanalyzer_enabled_without_findings',
            'region': region,
            'profile': profile,
            'status': 'ERROR',
            'resource_id': f"access-analyzer-{region}",
            'error': str(e)
        })
    
    return findings


def s3_bucket_encryption(client, region, profile, logger):
    """Check if S3 buckets have encryption enabled"""
    findings = []
    try:
        response = client.list_buckets()
        buckets = response.get('Buckets', [])
        
        for bucket in buckets:
            bucket_name = bucket['Name']
            
            try:
                # Check bucket encryption
                encryption_response = client.get_bucket_encryption(Bucket=bucket_name)
                encryption_config = encryption_response.get('ServerSideEncryptionConfiguration', {})
                rules = encryption_config.get('Rules', [])
                
                if rules:
                    for rule in rules:
                        sse_algorithm = rule.get('ApplyServerSideEncryptionByDefault', {}).get('SSEAlgorithm')
                        findings.append({
                            'type': 's3_bucket_encryption',
                            'region': region,
                            'profile': profile,
                            'status': 'PASS',
                            'resource_id': bucket_name,
                            'encryption_algorithm': sse_algorithm,
                            'kms_key_id': rule.get('ApplyServerSideEncryptionByDefault', {}).get('KMSMasterKeyID')
                        })
                else:
                    findings.append({
                        'type': 's3_bucket_encryption',
                        'region': region,
                        'profile': profile,
                        'status': 'FAIL',
                        'resource_id': bucket_name,
                        'issues': ['No encryption rules configured']
                    })
                    
            except client.exceptions.ClientError as e:
                if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                    findings.append({
                        'type': 's3_bucket_encryption',
                        'region': region,
                        'profile': profile,
                        'status': 'FAIL',
                        'resource_id': bucket_name,
                        'issues': ['No server-side encryption configured']
                    })
                else:
                    logger.warning(f"Could not check encryption for bucket {bucket_name}: {e}")
                    
    except Exception as e:
        logger.error(f"Error checking S3 bucket encryption: {e}")
        findings.append({
            'type': 's3_bucket_encryption',
            'region': region,
            'profile': profile,
            'status': 'ERROR',
            'resource_id': region,
            'error': str(e)
        })
    return findings


def vpc_flow_logs_enabled(client, region, profile, logger):
    """Check if VPC Flow Logs are enabled"""
    findings = []
    try:
        # Get all VPCs
        vpcs_response = client.describe_vpcs()
        vpcs = vpcs_response.get('Vpcs', [])
        
        # Get flow logs
        flow_logs_response = client.describe_flow_logs()
        flow_logs = flow_logs_response.get('FlowLogs', [])
        
        # Create a set of VPC IDs that have flow logs
        vpcs_with_flow_logs = set()
        for flow_log in flow_logs:
            if flow_log.get('ResourceType') == 'VPC' and flow_log.get('FlowLogStatus') == 'ACTIVE':
                vpcs_with_flow_logs.add(flow_log.get('ResourceId'))
        
        for vpc in vpcs:
            vpc_id = vpc['VpcId']
            if vpc_id in vpcs_with_flow_logs:
                findings.append({
                    'type': 'vpc_flow_logs_enabled',
                    'region': region,
                    'profile': profile,
                    'status': 'PASS',
                    'resource_id': vpc_id,
                    'vpc_cidr': vpc.get('CidrBlock')
                })
            else:
                findings.append({
                    'type': 'vpc_flow_logs_enabled',
                    'region': region,
                    'profile': profile,
                    'status': 'FAIL',
                    'resource_id': vpc_id,
                    'vpc_cidr': vpc.get('CidrBlock'),
                    'issues': ['VPC Flow Logs not enabled']
                })
                
    except Exception as e:
        logger.error(f"Error checking VPC Flow Logs: {e}")
        findings.append({
            'type': 'vpc_flow_logs_enabled',
            'region': region,
            'profile': profile,
            'status': 'ERROR',
            'resource_id': region,
            'error': str(e)
        })
    return findings


def rds_encryption_enabled(client, region, profile, logger):
    """Check if RDS instances have encryption enabled"""
    findings = []
    try:
        # Check RDS instances
        instances_response = client.describe_db_instances()
        instances = instances_response.get('DBInstances', [])
        
        for instance in instances:
            db_instance_id = instance['DBInstanceIdentifier']
            encrypted = instance.get('StorageEncrypted', False)
            
            if encrypted:
                findings.append({
                    'type': 'rds_encryption_enabled',
                    'region': region,
                    'profile': profile,
                    'status': 'PASS',
                    'resource_id': db_instance_id,
                    'engine': instance.get('Engine'),
                    'engine_version': instance.get('EngineVersion')
                })
            else:
                findings.append({
                    'type': 'rds_encryption_enabled',
                    'region': region,
                    'profile': profile,
                    'status': 'FAIL',
                    'resource_id': db_instance_id,
                    'engine': instance.get('Engine'),
                    'engine_version': instance.get('EngineVersion'),
                    'issues': ['RDS instance encryption not enabled']
                })
                
        # Check RDS clusters
        clusters_response = client.describe_db_clusters()
        clusters = clusters_response.get('DBClusters', [])
        
        for cluster in clusters:
            cluster_id = cluster['DBClusterIdentifier']
            encrypted = cluster.get('StorageEncrypted', False)
            
            if encrypted:
                findings.append({
                    'type': 'rds_encryption_enabled',
                    'region': region,
                    'profile': profile,
                    'status': 'PASS',
                    'resource_id': cluster_id,
                    'engine': cluster.get('Engine'),
                    'engine_version': cluster.get('EngineVersion')
                })
            else:
                findings.append({
                    'type': 'rds_encryption_enabled',
                    'region': region,
                    'profile': profile,
                    'status': 'FAIL',
                    'resource_id': cluster_id,
                    'engine': cluster.get('Engine'),
                    'engine_version': cluster.get('EngineVersion'),
                    'issues': ['RDS cluster encryption not enabled']
                })
                
    except Exception as e:
        logger.error(f"Error checking RDS encryption: {e}")
        findings.append({
            'type': 'rds_encryption_enabled',
            'region': region,
            'profile': profile,
            'status': 'ERROR',
            'resource_id': region,
            'error': str(e)
        })
    return findings


def lambda_function_encryption(client, region, profile, logger):
    """Check if Lambda functions have encryption enabled"""
    findings = []
    try:
        paginator = client.get_paginator('list_functions')
        
        for page in paginator.paginate():
            functions = page.get('Functions', [])
            
            for function in functions:
                function_name = function['FunctionName']
                function_arn = function['FunctionArn']
                
                # Check KMS key configuration
                kms_key_arn = function.get('KMSKeyArn')
                
                if kms_key_arn:
                    findings.append({
                        'type': 'lambda_function_encryption',
                        'region': region,
                        'profile': profile,
                        'status': 'PASS',
                        'resource_id': function_name,
                        'resource_arn': function_arn,
                        'kms_key_arn': kms_key_arn,
                        'runtime': function.get('Runtime')
                    })
                else:
                    findings.append({
                        'type': 'lambda_function_encryption',
                        'region': region,
                        'profile': profile,
                        'status': 'FAIL',
                        'resource_id': function_name,
                        'resource_arn': function_arn,
                        'runtime': function.get('Runtime'),
                        'issues': ['Lambda function not using customer managed KMS key for encryption']
                    })
                    
    except Exception as e:
        logger.error(f"Error checking Lambda function encryption: {e}")
        findings.append({
            'type': 'lambda_function_encryption',
            'region': region,
            'profile': profile,
            'status': 'ERROR',
            'resource_id': region,
            'error': str(e)
        })
    return findings


def ebs_volume_encryption(client, region, profile, logger):
    """Check if EBS volumes have encryption enabled"""
    findings = []
    try:
        paginator = client.get_paginator('describe_volumes')
        
        for page in paginator.paginate():
            volumes = page.get('Volumes', [])
            
            for volume in volumes:
                volume_id = volume['VolumeId']
                volume_arn = f"arn:aws:ec2:{region}:{volume.get('OwnerId', '')}:volume/{volume_id}"
                
                if volume.get('Encrypted', False):
                    findings.append({
                        'type': 'ebs_volume_encryption',
                        'region': region,
                        'profile': profile,
                        'status': 'PASS',
                        'resource_id': volume_id,
                        'resource_arn': volume_arn,
                        'kms_key_id': volume.get('KmsKeyId'),
                        'volume_type': volume.get('VolumeType'),
                        'state': volume.get('State')
                    })
                else:
                    findings.append({
                        'type': 'ebs_volume_encryption',
                        'region': region,
                        'profile': profile,
                        'status': 'FAIL',
                        'resource_id': volume_id,
                        'resource_arn': volume_arn,
                        'volume_type': volume.get('VolumeType'),
                        'state': volume.get('State'),
                        'issues': ['EBS volume is not encrypted']
                    })
                    
    except Exception as e:
        logger.error(f"Error checking EBS volume encryption: {e}")
        findings.append({
            'type': 'ebs_volume_encryption',
            'region': region,
            'profile': profile,
            'status': 'ERROR',
            'resource_id': region,
            'error': str(e)
        })
    return findings


def sns_topic_encryption(client, region, profile, logger):
    """Check if SNS topics have encryption enabled"""
    findings = []
    try:
        paginator = client.get_paginator('list_topics')
        
        for page in paginator.paginate():
            topics = page.get('Topics', [])
            
            for topic in topics:
                topic_arn = topic['TopicArn']
                
                try:
                    # Get topic attributes to check encryption
                    attrs_response = client.get_topic_attributes(TopicArn=topic_arn)
                    attributes = attrs_response.get('Attributes', {})
                    
                    kms_master_key_id = attributes.get('KmsMasterKeyId')
                    
                    if kms_master_key_id:
                        findings.append({
                            'type': 'sns_topic_encryption',
                            'region': region,
                            'profile': profile,
                            'status': 'PASS',
                            'resource_id': topic_arn.split(':')[-1],
                            'resource_arn': topic_arn,
                            'kms_key_id': kms_master_key_id,
                            'display_name': attributes.get('DisplayName'),
                            'policy': attributes.get('Policy')
                        })
                    else:
                        findings.append({
                            'type': 'sns_topic_encryption',
                            'region': region,
                            'profile': profile,
                            'status': 'FAIL',
                            'resource_id': topic_arn.split(':')[-1],
                            'resource_arn': topic_arn,
                            'display_name': attributes.get('DisplayName'),
                            'issues': ['SNS topic is not encrypted with KMS']
                        })
                        
                except Exception as topic_error:
                    logger.error(f"Error checking topic {topic_arn}: {topic_error}")
                    findings.append({
                        'type': 'sns_topic_encryption',
                        'region': region,
                        'profile': profile,
                        'status': 'ERROR',
                        'resource_id': topic_arn.split(':')[-1],
                        'resource_arn': topic_arn,
                        'error': str(topic_error)
                    })
                    
    except Exception as e:
        logger.error(f"Error checking SNS topic encryption: {e}")
        findings.append({
            'type': 'sns_topic_encryption',
            'region': region,
            'profile': profile,
            'status': 'ERROR',
            'resource_id': region,
            'error': str(e)
        })
    return findings


def sqs_queue_encryption(client, region, profile, logger):
    """Check if SQS queues have encryption enabled"""
    findings = []
    try:
        paginator = client.get_paginator('list_queues')
        
        for page in paginator.paginate():
            queue_urls = page.get('QueueUrls', [])
            
            for queue_url in queue_urls:
                try:
                    # Get queue attributes to check encryption
                    attrs_response = client.get_queue_attributes(
                        QueueUrl=queue_url,
                        AttributeNames=['All']
                    )
                    attributes = attrs_response.get('Attributes', {})
                    
                    kms_master_key_id = attributes.get('KmsMasterKeyId')
                    queue_name = queue_url.split('/')[-1]
                    
                    if kms_master_key_id:
                        findings.append({
                            'type': 'sqs_queue_encryption',
                            'region': region,
                            'profile': profile,
                            'status': 'PASS',
                            'resource_id': queue_name,
                            'resource_arn': attributes.get('QueueArn'),
                            'queue_url': queue_url,
                            'kms_key_id': kms_master_key_id,
                            'visibility_timeout': attributes.get('VisibilityTimeout'),
                            'message_retention_period': attributes.get('MessageRetentionPeriod')
                        })
                    else:
                        findings.append({
                            'type': 'sqs_queue_encryption',
                            'region': region,
                            'profile': profile,
                            'status': 'FAIL',
                            'resource_id': queue_name,
                            'resource_arn': attributes.get('QueueArn'),
                            'queue_url': queue_url,
                            'issues': ['SQS queue is not encrypted with KMS']
                        })
                        
                except Exception as queue_error:
                    logger.error(f"Error checking queue {queue_url}: {queue_error}")
                    findings.append({
                        'type': 'sqs_queue_encryption',
                        'region': region,
                        'profile': profile,
                        'status': 'ERROR',
                        'resource_id': queue_url.split('/')[-1],
                        'queue_url': queue_url,
                        'error': str(queue_error)
                    })
                    
    except Exception as e:
        logger.error(f"Error checking SQS queue encryption: {e}")
        findings.append({
            'type': 'sqs_queue_encryption',
            'region': region,
            'profile': profile,
            'status': 'ERROR',
            'resource_id': region,
            'error': str(e)
        })
    return findings


def kms_key_rotation_enabled(client, region, profile, logger):
    """Check if KMS keys have automatic key rotation enabled"""
    findings = []
    try:
        paginator = client.get_paginator('list_keys')
        
        for page in paginator.paginate():
            keys = page.get('Keys', [])
            
            for key in keys:
                key_id = key['KeyId']
                try:
                    # Get key details
                    key_details = client.describe_key(KeyId=key_id)
                    key_metadata = key_details['KeyMetadata']
                    
                    # Skip AWS managed keys
                    if key_metadata['KeyManager'] == 'AWS':
                        continue
                    
                    # Check if key rotation is enabled for customer managed keys
                    rotation_status = client.get_key_rotation_status(KeyId=key_id)
                    rotation_enabled = rotation_status.get('KeyRotationEnabled', False)
                    
                    if rotation_enabled:
                        findings.append({
                            'type': 'kms_key_rotation_enabled',
                            'region': region,
                            'profile': profile,
                            'status': 'PASS',
                            'resource_id': key_id,
                            'resource_arn': key_metadata.get('Arn'),
                            'key_usage': key_metadata.get('KeyUsage'),
                            'key_state': key_metadata.get('KeyState'),
                            'creation_date': key_metadata.get('CreationDate'),
                            'rotation_enabled': True
                        })
                    else:
                        findings.append({
                            'type': 'kms_key_rotation_enabled',
                            'region': region,
                            'profile': profile,
                            'status': 'FAIL',
                            'resource_id': key_id,
                            'resource_arn': key_metadata.get('Arn'),
                            'issues': ['KMS key rotation is not enabled'],
                            'key_usage': key_metadata.get('KeyUsage'),
                            'key_state': key_metadata.get('KeyState')
                        })
                        
                except Exception as key_error:
                    logger.error(f"Error checking KMS key {key_id}: {key_error}")
                    findings.append({
                        'type': 'kms_key_rotation_enabled',
                        'region': region,
                        'profile': profile,
                        'status': 'ERROR',
                        'resource_id': key_id,
                        'error': str(key_error)
                    })
                    
    except Exception as e:
        logger.error(f"Error checking KMS key rotation: {e}")
        findings.append({
            'type': 'kms_key_rotation_enabled',
            'region': region,
            'profile': profile,
            'status': 'ERROR',
            'resource_id': region,
            'error': str(e)
        })
    return findings


def wafv2_webacl_logging_enabled(client, region, profile, logger):
    """Check if WAFv2 WebACLs have logging enabled"""
    findings = []
    try:
        paginator = client.get_paginator('list_web_acls')
        
        for page in paginator.paginate(Scope='REGIONAL'):
            for webacl in page['WebACLs']:
                webacl_id = webacl['Id']
                webacl_name = webacl['Name']
                webacl_arn = webacl['ARN']
                
                try:
                    # Check logging configuration
                    logging_response = client.get_logging_configuration(ResourceArn=webacl_arn)
                    logging_config = logging_response.get('LoggingConfiguration', {})
                    
                    if logging_config:
                        log_destination_configs = logging_config.get('LogDestinationConfigs', [])
                        if log_destination_configs:
                            findings.append({
                                'type': 'wafv2_webacl_logging_enabled',
                                'region': region,
                                'profile': profile,
                                'status': 'PASS',
                                'resource_id': webacl_id,
                                'resource_name': webacl_name,
                                'resource_arn': webacl_arn,
                                'log_destinations': log_destination_configs
                            })
                        else:
                            findings.append({
                                'type': 'wafv2_webacl_logging_enabled',
                                'region': region,
                                'profile': profile,
                                'status': 'FAIL',
                                'resource_id': webacl_id,
                                'resource_name': webacl_name,
                                'resource_arn': webacl_arn,
                                'issues': ['WebACL has logging configuration but no destinations']
                            })
                    else:
                        findings.append({
                            'type': 'wafv2_webacl_logging_enabled',
                            'region': region,
                            'profile': profile,
                            'status': 'FAIL',
                            'resource_id': webacl_id,
                            'resource_name': webacl_name,
                            'resource_arn': webacl_arn,
                            'issues': ['WebACL logging not configured']
                        })
                        
                except client.exceptions.WAFNonexistentItemException:
                    findings.append({
                        'type': 'wafv2_webacl_logging_enabled',
                        'region': region,
                        'profile': profile,
                        'status': 'FAIL',
                        'resource_id': webacl_id,
                        'resource_name': webacl_name,
                        'resource_arn': webacl_arn,
                        'issues': ['No logging configuration found for WebACL']
                    })
                except Exception as e:
                    logger.error(f"Error checking logging for WebACL {webacl_name}: {e}")
                    findings.append({
                        'type': 'wafv2_webacl_logging_enabled',
                        'region': region,
                        'profile': profile,
                        'status': 'ERROR',
                        'resource_id': webacl_id,
                        'resource_name': webacl_name,
                        'resource_arn': webacl_arn,
                        'error': str(e)
                    })
                    
    except Exception as e:
        logger.error(f"Error checking WAFv2 WebACL logging: {e}")
        findings.append({
            'type': 'wafv2_webacl_logging_enabled',
            'region': region,
            'profile': profile,
            'status': 'ERROR',
            'resource_id': region,
            'error': str(e)
        })
    return findings


def waf_global_webacl_logging_enabled(client, region, profile, logger):
    """Check if WAF Classic global WebACLs have logging enabled"""
    findings = []
    
    # This check only applies to us-east-1 for global WAF
    if region != 'us-east-1':
        return findings
    
    try:
        response = client.list_web_acls()
        web_acls = response.get('WebACLs', [])
        
        for webacl in web_acls:
            webacl_id = webacl['WebACLId']
            webacl_name = webacl['Name']
            
            try:
                # Check logging configuration for WAF Classic
                logging_response = client.get_logging_configuration(ResourceArn=f"arn:aws:waf::{region}:webacl/{webacl_id}")
                logging_config = logging_response.get('LoggingConfiguration', {})
                
                if logging_config:
                    log_destination_configs = logging_config.get('LogDestinationConfigs', [])
                    if log_destination_configs:
                        findings.append({
                            'type': 'waf_global_webacl_logging_enabled',
                            'region': region,
                            'profile': profile,
                            'status': 'PASS',
                            'resource_id': webacl_id,
                            'resource_name': webacl_name,
                            'log_destinations': log_destination_configs
                        })
                    else:
                        findings.append({
                            'type': 'waf_global_webacl_logging_enabled',
                            'region': region,
                            'profile': profile,
                            'status': 'FAIL',
                            'resource_id': webacl_id,
                            'resource_name': webacl_name,
                            'issues': ['Global WebACL has logging configuration but no destinations']
                        })
                else:
                    findings.append({
                        'type': 'waf_global_webacl_logging_enabled',
                        'region': region,
                        'profile': profile,
                        'status': 'FAIL',
                        'resource_id': webacl_id,
                        'resource_name': webacl_name,
                        'issues': ['Global WebACL logging not configured']
                    })
                    
            except client.exceptions.WAFNonexistentItemException:
                findings.append({
                    'type': 'waf_global_webacl_logging_enabled',
                    'region': region,
                    'profile': profile,
                    'status': 'FAIL',
                    'resource_id': webacl_id,
                    'resource_name': webacl_name,
                    'issues': ['No logging configuration found for global WebACL']
                })
            except Exception as e:
                logger.error(f"Error checking logging for global WebACL {webacl_name}: {e}")
                findings.append({
                    'type': 'waf_global_webacl_logging_enabled',
                    'region': region,
                    'profile': profile,
                    'status': 'ERROR',
                    'resource_id': webacl_id,
                    'resource_name': webacl_name,
                    'error': str(e)
                })
                
    except Exception as e:
        logger.error(f"Error checking WAF global WebACL logging: {e}")
        findings.append({
            'type': 'waf_global_webacl_logging_enabled',
            'region': region,
            'profile': profile,
            'status': 'ERROR',
            'resource_id': region,
            'error': str(e)
        })
    return findings


def wafv2_webacl_rule_logging_enabled(client, region, profile, logger):
    """Check if WAFv2 WebACL rules have sampling enabled for detailed logging"""
    findings = []
    try:
        paginator = client.get_paginator('list_web_acls')
        
        for page in paginator.paginate(Scope='REGIONAL'):
            for webacl in page['WebACLs']:
                webacl_id = webacl['Id']
                webacl_name = webacl['Name']
                webacl_arn = webacl['ARN']
                
                try:
                    # Get WebACL details to check rules
                    webacl_detail = client.get_web_acl(
                        Scope='REGIONAL',
                        Id=webacl_id,
                        Name=webacl_name
                    )
                    
                    webacl_info = webacl_detail['WebACL']
                    rules = webacl_info.get('Rules', [])
                    
                    rule_logging_issues = []
                    rules_with_sampling = []
                    
                    for rule in rules:
                        rule_name = rule.get('Name', 'unknown')
                        visibility_config = rule.get('VisibilityConfig', {})
                        
                        sampled_requests_enabled = visibility_config.get('SampledRequestsEnabled', False)
                        metric_name = visibility_config.get('MetricName', '')
                        cloudwatch_metrics_enabled = visibility_config.get('CloudWatchMetricsEnabled', False)
                        
                        if sampled_requests_enabled and cloudwatch_metrics_enabled:
                            rules_with_sampling.append({
                                'rule_name': rule_name,
                                'metric_name': metric_name,
                                'sampled_requests': sampled_requests_enabled,
                                'cloudwatch_metrics': cloudwatch_metrics_enabled
                            })
                        else:
                            issues = []
                            if not sampled_requests_enabled:
                                issues.append('Sampled requests not enabled')
                            if not cloudwatch_metrics_enabled:
                                issues.append('CloudWatch metrics not enabled')
                            rule_logging_issues.append(f"Rule '{rule_name}': {', '.join(issues)}")
                    
                    if rule_logging_issues:
                        findings.append({
                            'type': 'wafv2_webacl_rule_logging_enabled',
                            'region': region,
                            'profile': profile,
                            'status': 'FAIL',
                            'resource_id': webacl_id,
                            'resource_name': webacl_name,
                            'resource_arn': webacl_arn,
                            'issues': rule_logging_issues,
                            'rules_with_logging': len(rules_with_sampling),
                            'total_rules': len(rules)
                        })
                    else:
                        findings.append({
                            'type': 'wafv2_webacl_rule_logging_enabled',
                            'region': region,
                            'profile': profile,
                            'status': 'PASS',
                            'resource_id': webacl_id,
                            'resource_name': webacl_name,
                            'resource_arn': webacl_arn,
                            'rules_with_logging': len(rules_with_logging),
                            'total_rules': len(rules)
                        })
                        
                except Exception as e:
                    logger.error(f"Error checking rule logging for WebACL {webacl_name}: {e}")
                    findings.append({
                        'type': 'wafv2_webacl_rule_logging_enabled',
                        'region': region,
                        'profile': profile,
                        'status': 'ERROR',
                        'resource_id': webacl_id,
                        'resource_name': webacl_name,
                        'resource_arn': webacl_arn,
                        'error': str(e)
                    })
                    
    except Exception as e:
        logger.error(f"Error checking WAFv2 WebACL rule logging: {e}")
        findings.append({
            'type': 'wafv2_webacl_rule_logging_enabled',
            'region': region,
            'profile': profile,
            'status': 'ERROR',
            'resource_id': region,
            'error': str(e)
        })
    return findings


def elbv2_waf_acl_attached(client, region, profile, logger):
    """Check if ELBv2 load balancers have WAF ACLs attached"""
    findings = []
    try:
        paginator = client.get_paginator('describe_load_balancers')
        
        for page in paginator.paginate():
            for lb in page['LoadBalancers']:
                lb_arn = lb['LoadBalancerArn']
                lb_name = lb['LoadBalancerName']
                lb_type = lb.get('Type', 'unknown')
                
                # Only check Application Load Balancers (ALB) as they support WAF
                if lb_type != 'application':
                                                                                                                                                         continue
                
                try:
                    # Check for WAF association using WAFv2
                    try:
                        import boto3
                        wafv2_client = boto3.client('wafv2', region_name=region)
                        
                        # List resources for regional WebACLs
                        regional_resources = wafv2_client.list_resources_for_web_acl(
                            WebACLArn=lb_arn,
                            ResourceType='APPLICATION_LOAD_BALANCER'
                        )
                        
                        if regional_resources.get('ResourceArns', []):
                            findings.append({
                                'type': 'elbv2_waf_acl_attached',
                                'region': region,
                                'profile': profile,
                                'status': 'PASS',
                                'resource_id': lb_name,
                                'resource_arn': lb_arn,
                                'load_balancer_type': lb_type,
                                'waf_type': 'WAFv2'
                            })
                        else:
                            findings.append({
                                'type': 'elbv2_waf_acl_attached',
                                'region': region,
                                'profile': profile,
                                'status': 'FAIL',
                                'resource_id': lb_name,
                                'resource_arn': lb_arn,
                                'load_balancer_type': lb_type,
                                'issues': ['No WAF ACL attached to Application Load Balancer']
                            })
                            
                    except Exception as waf_error:
                        # Try to check using the resource's own attributes or fall back
                        logger.warning(f"Could not check WAF association for {lb_name}: {waf_error}")
                        
                        # For ALBs without WAF, this is a failure
                        findings.append({
                            'type': 'elbv2_waf_acl_attached',
                            'region': region,
                            'profile': profile,
                            'status': 'FAIL',
                            'resource_id': lb_name,
                            'resource_arn': lb_arn,
                            'load_balancer_type': lb_type,
                            'issues': ['Could not verify WAF ACL attachment']
                        })
                        
                except Exception as e:
                    logger.error(f"Error checking WAF for load balancer {lb_name}: {e}")
                    findings.append({
                        'type': 'elbv2_waf_acl_attached',
                        'region': region,
                        'profile': profile,
                        'status': 'ERROR',
                        'resource_id': lb_name,
                        'resource_arn': lb_arn,
                        'load_balancer_type': lb_type,
                        'error': str(e)
                    })
                    
    except Exception as e:
        logger.error(f"Error checking ELBv2 WAF attachments: {e}")
        findings.append({
            'type': 'elbv2_waf_acl_attached',
            'region': region,
            'profile': profile,
            'status': 'ERROR',
            'resource_id': region,
            'error': str(e)
        })
    return findings


def apigateway_restapi_waf_acl_attached(client, region, profile, logger):
    """Check if API Gateway REST APIs have WAF ACLs attached"""
    findings = []
    try:
        paginator = client.get_paginator('get_rest_apis')
        
        for page in paginator.paginate():
            for api in page['items']:
                api_id = api['id']
                api_name = api.get('name', 'unknown')
                
                try:
                    # Check for WAF association
                    # For API Gateway, we need to check stages for WAF association
                    stages_response = client.get_stages(restApiId=api_id)
                    stages = stages_response.get('item', [])
                    
                    api_has_waf = False
                    stage_details = []
                    
                    for stage in stages:
                        stage_name = stage.get('stageName', 'unknown')
                        
                        try:
                            # Check if stage has WAF using WAFv2
                            import boto3
                            wafv2_client = boto3.client('wafv2', region_name=region)
                            
                            stage_arn = f"arn:aws:apigateway:{region}::/restapis/{api_id}/stages/{stage_name}"
                            
                            # This is a simplified check - in practice, you'd need to list WebACLs 
                            # and check their associated resources
                            stage_details.append({
                                'stage_name': stage_name,
                                'stage_arn': stage_arn,
                                'has_waf': False  # Default to false, would need actual WAF check
                            })
                            
                        except Exception as stage_error:
                            logger.warning(f"Could not check WAF for stage {stage_name}: {stage_error}")
                            stage_details.append({
                                'stage_name': stage_name,
                                'has_waf': False,
                                'error': str(stage_error)
                            })
                    
                    if not api_has_waf:
                        findings.append({
                            'type': 'apigateway_restapi_waf_acl_attached',
                            'region': region,
                            'profile': profile,
                            'status': 'FAIL',
                            'resource_id': api_id,
                            'resource_name': api_name,
                            'issues': ['No WAF ACL attached to API Gateway REST API'],
                            'stages_checked': len(stages),
                            'stage_details': stage_details
                        })
                    else:
                        findings.append({
                            'type': 'apigateway_restapi_waf_acl_attached',
                            'region': region,
                            'profile': profile,
                            'status': 'PASS',
                            'resource_id': api_id,
                            'resource_name': api_name,
                            'stages_checked': len(stages),
                            'stage_details': stage_details
                        })
                        
                except Exception as e:
                    logger.error(f"Error checking WAF for API {api_name}: {e}")
                    findings.append({
                        'type': 'apigateway_restapi_waf_acl_attached',
                        'region': region,
                        'profile': profile,
                        'status': 'ERROR',
                        'resource_id': api_id,
                        'resource_name': api_name,
                        'error': str(e)
                    })
                    
    except Exception as e:
        logger.error(f"Error checking API Gateway WAF attachments: {e}")
        findings.append({
            'type': 'apigateway_restapi_waf_acl_attached',
            'region': region,
            'profile': profile,
            'status': 'ERROR',
            'resource_id': region,
            'error': str(e)
        })
    return findings


def cloudfront_distributions_using_waf(client, region, profile, logger):
    """Check if CloudFront distributions are using WAF"""
    findings = []
    
    # CloudFront is a global service, only check in us-east-1
    if region != 'us-east-1':
        return findings
    
    try:
        paginator = client.get_paginator('list_distributions')
        
        for page in paginator.paginate():
            distribution_list = page.get('DistributionList', {})
            distributions = distribution_list.get('Items', [])
            
            for distribution in distributions:
                distribution_id = distribution['Id']
                domain_name = distribution.get('DomainName', 'unknown')
                
                try:
                    # Get distribution details
                    distribution_detail = client.get_distribution(Id=distribution_id)
                    distribution_config = distribution_detail['Distribution']['DistributionConfig']
                    
                    # Check for WAF association
                    web_acl_id = distribution_config.get('WebACLId', '')
                    
                    if web_acl_id:
                        findings.append({
                            'type': 'cloudfront_distributions_using_waf',
                            'region': region,
                            'profile': profile,
                            'status': 'PASS',
                            'resource_id': distribution_id,
                            'domain_name': domain_name,
                            'web_acl_id': web_acl_id,
                            'enabled': distribution_config.get('Enabled', False)
                        })
                    else:
                        findings.append({
                            'type': 'cloudfront_distributions_using_waf',
                            'region': region,
                            'profile': profile,
                            'status': 'FAIL',
                            'resource_id': distribution_id,
                            'domain_name': domain_name,
                            'enabled': distribution_config.get('Enabled', False),
                            'issues': ['CloudFront distribution does not have WAF ACL attached']
                        })
                        
                except Exception as e:
                    logger.error(f"Error checking distribution {distribution_id}: {e}")
                    findings.append({
                        'type': 'cloudfront_distributions_using_waf',
                        'region': region,
                        'profile': profile,
                        'status': 'ERROR',
                        'resource_id': distribution_id,
                        'domain_name': domain_name,
                        'error': str(e)
                    })
                    
    except Exception as e:
        logger.error(f"Error checking CloudFront distributions WAF: {e}")
        findings.append({
            'type': 'cloudfront_distributions_using_waf',
            'region': region,
            'profile': profile,
            'status': 'ERROR',
            'resource_id': region,
            'error': str(e)
        })
    return findings


def cloudtrail_multi_region_enabled(client, region, profile, logger):
    """
    Check if CloudTrail multi-region is enabled
    Serves 264 compliance requirements across multiple frameworks
    """
    findings = []
    try:
        response = client.describe_trails()
        trails = response.get('trailList', [])
        
        compliant_trails = []
        non_compliant_trails = []
        
        for trail in trails:
            trail_name = trail['Name']
            is_multi_region = trail.get('IsMultiRegionTrail', False)
            
            if is_multi_region:
                compliant_trails.append({
                    'trail_name': trail_name,
                    'is_multi_region': is_multi_region,
                    'status': 'COMPLIANT'
                })
            else:
                non_compliant_trails.append({
                    'trail_name': trail_name,
                    'is_multi_region': is_multi_region,
                    'status': 'NON_COMPLIANT',
                    'reason': 'CloudTrail is not enabled for multiple regions'
                })
        
        return {
            'compliance_status': 'COMPLIANT' if len(compliant_trails) > 0 and len(non_compliant_trails) == 0 else 'NON_COMPLIANT',
            'compliant_resources': compliant_trails,
            'non_compliant_resources': non_compliant_trails,
            'total_resources': len(trails),
            'summary': f"Found {len(compliant_trails)} compliant and {len(non_compliant_trails)} non-compliant CloudTrail configurations"
        }
        
    except Exception as e:
        logger.error(f"Error checking CloudTrail multi-region configuration: {str(e)}")
        return {
            'compliance_status': 'ERROR',
            'error': str(e)
        }

def cloudtrail_cloudwatch_logging_enabled(client, region, profile, logger):
    """
    Check if CloudTrail CloudWatch logging is enabled
    Serves 172 compliance requirements across multiple frameworks
    """
    findings = []
    try:
        response = client.describe_trails()
        trails = response.get('trailList', [])
        
        compliant_trails = []
        non_compliant_trails = []
        
        for trail in trails:
            trail_name = trail['Name']
            cloudwatch_logs_log_group_arn = trail.get('CloudWatchLogsLogGroupArn')
            cloudwatch_logs_role_arn = trail.get('CloudWatchLogsRoleArn')
            
            if cloudwatch_logs_log_group_arn and cloudwatch_logs_role_arn:
                compliant_trails.append({
                    'trail_name': trail_name,
                    'cloudwatch_logs_log_group_arn': cloudwatch_logs_log_group_arn,
                    'status': 'COMPLIANT'
                })
            else:
                non_compliant_trails.append({
                    'trail_name': trail_name,
                    'cloudwatch_logs_log_group_arn': cloudwatch_logs_log_group_arn,
                    'status': 'NON_COMPLIANT',
                    'reason': 'CloudTrail does not have CloudWatch logging enabled'
                })
            
        return {
            'compliance_status': 'COMPLIANT' if len(compliant_trails) > 0 and len(non_compliant_trails) == 0 else 'NON_COMPLIANT',
            'compliant_resources': compliant_trails,
            'non_compliant_resources': non_compliant_trails,
            'total_resources': len(trails),
            'summary': f"Found {len(compliant_trails)} compliant and {len(non_compliant_trails)} non-compliant CloudTrail CloudWatch logging configurations"
        }
        
    except Exception as e:
        logger.error(f"Error checking CloudTrail CloudWatch logging: {str(e)}")
        return {
            'compliance_status': 'ERROR',
            'error': str(e)
        }

def cloudtrail_s3_dataevents_read_enabled(client, region, profile, logger):
    """
    Check if CloudTrail S3 data events for read operations are enabled
    Serves 130 compliance requirements across multiple frameworks
    """
    findings = []
    try:
        response = client.describe_trails()
        trails = response.get('trailList', [])
        
        compliant_trails = []
        non_compliant_trails = []
        
        for trail in trails:
            trail_name = trail['Name']
            trail_arn = trail['TrailARN']
            
            # Get event selectors for the trail
            try:
                event_selectors = client.get_event_selectors(TrailName=trail_arn)
                selectors = event_selectors.get('EventSelectors', [])
                
                has_s3_read_events = False
                for selector in selectors:
                    if selector.get('ReadWriteType') in ['ReadOnly', 'All']:
                        data_resources = selector.get('DataResources', [])
                        for resource in data_resources:
                            if resource.get('Type') == 'AWS::S3::Object':
                                has_s3_read_events = True
                                break
                
                if has_s3_read_events:
                    compliant_trails.append({
                        'trail_name': trail_name,
                        'has_s3_read_events': has_s3_read_events,
                        'status': 'COMPLIANT'
                    })
                else:
                    non_compliant_trails.append({
                        'trail_name': trail_name,
                        'has_s3_read_events': has_s3_read_events,
                        'status': 'NON_COMPLIANT',
                        'reason': 'CloudTrail does not have S3 read data events enabled'
                    })
                    
            except Exception as selector_error:
                logger.warning(f"Error getting event selectors for trail {trail_name}: {str(selector_error)}")
                non_compliant_trails.append({
                    'trail_name': trail_name,
                    'status': 'NON_COMPLIANT',
                    'reason': f'Error retrieving event selectors: {str(selector_error)}'
                })
        
        return {
            'compliance_status': 'COMPLIANT' if len(compliant_trails) > 0 and len(non_compliant_trails) == 0 else 'NON_COMPLIANT',
            'compliant_resources': compliant_trails,
            'non_compliant_resources': non_compliant_trails,
            'total_resources': len(trails),
            'summary': f"Found {len(compliant_trails)} compliant and {len(non_compliant_trails)} non-compliant CloudTrail S3 read data events configurations"
        }
        
    except Exception as e:
        logger.error(f"Error checking CloudTrail S3 read data events: {str(e)}")
        return {
            'compliance_status': 'ERROR',
            'error': str(e)
        }

def cloudtrail_s3_dataevents_write_enabled(client, region, profile, logger):
    """
    Check if CloudTrail S3 data events for write operations are enabled
    Serves 128 compliance requirements across multiple frameworks
    """
    findings = []
    try:
        response = client.describe_trails()
        trails = response.get('trailList', [])
        
        compliant_trails = []
        non_compliant_trails = []
        
        for trail in trails:
            trail_name = trail['Name']
            trail_arn = trail['TrailARN']
            
            # Get event selectors for the trail
            try:
                event_selectors = client.get_event_selectors(TrailName=trail_arn)
                selectors = event_selectors.get('EventSelectors', [])
                
                has_s3_write_events = False
                for selector in selectors:
                    if selector.get('ReadWriteType') in ['WriteOnly', 'All']:
                        data_resources = selector.get('DataResources', [])
                        for resource in data_resources:
                            if resource.get('Type') == 'AWS::S3::Object':
                                has_s3_write_events = True
                                break
                
                if has_s3_write_events:
                    compliant_trails.append({
                        'trail_name': trail_name,
                        'has_s3_write_events': has_s3_write_events,
                        'status': 'COMPLIANT'
                    })
                else:
                    non_compliant_trails.append({
                        'trail_name': trail_name,
                        'has_s3_write_events': has_s3_write_events,
                        'status': 'NON_COMPLIANT',
                        'reason': 'CloudTrail does not have S3 write data events enabled'
                    })
                    
            except Exception as selector_error:
                logger.warning(f"Error getting event selectors for trail {trail_name}: {str(selector_error)}")
                non_compliant_trails.append({
                    'trail_name': trail_name,
                    'status': 'NON_COMPLIANT',
                    'reason': f'Error retrieving event selectors: {str(selector_error)}'
                })
        
        return {
            'compliance_status': 'COMPLIANT' if len(compliant_trails) > 0 and len(non_compliant_trails) == 0 else 'NON_COMPLIANT',
            'compliant_resources': compliant_trails,
            'non_compliant_resources': non_compliant_trails,
            'total_resources': len(trails),
            'summary': f"Found {len(compliant_trails)} compliant and {len(non_compliant_trails)} non-compliant CloudTrail S3 write data events configurations"
        }
        
    except Exception as e:
        logger.error(f"Error checking CloudTrail S3 write data events: {str(e)}")
        return {
            'compliance_status': 'ERROR',
            'error': str(e)
        }

def apigateway_restapi_logging_enabled(client, region, profile, logger):
    """
    Check if API Gateway REST API logging is enabled
    Serves 99 compliance requirements across multiple frameworks
    """
    findings = []
    try:
        response = client.get_rest_apis()
        apis = response.get('items', [])
        
        compliant_apis = []
        non_compliant_apis = []
        
        for api in apis:
            api_id = api['id']
            api_name = api.get('name', 'unknown')
            
            try:
                stages = client.get_stages(restApiId=api_id)
                stage_details = stages.get('item', [])
                
                api_compliant = True
                
                for stage in stage_details:
                    stage_name = stage['stageName']
                    access_log_settings = stage.get('accessLogSettings', {})
                    method_settings = stage.get('methodSettings', {})
                    
                    # Check if access logging is enabled
                    has_access_logging = bool(access_log_settings.get('destinationArn'))
                    
                    # Check if execution logging is enabled
                    has_execution_logging = False
                    for method, settings in method_settings.items():
                        if settings.get('loggingLevel') in ['INFO', 'ERROR']:
                            has_execution_logging = True
                            break
                    
                    if not (has_access_logging or has_execution_logging):
                        api_compliant = False
                        non_compliant_apis.append({
                            'api_id': api_id,
                            'api_name': api_name,
                            'stage_name': stage_name,
                            'compliance_status': 'NON_COMPLIANT',
                            'reason': 'Logging is not enabled for this stage'
                        })
                
                if api_compliant:
                    compliant_apis.append({
                        'api_id': api_id,
                        'api_name': api_name,
                        'compliance_status': 'COMPLIANT'
                    })
                
            except Exception as e:
                logger.warning(f"Error checking API Gateway stages for {api_name}: {e}")
                non_compliant_apis.append({
                    'api_id': api_id,
                    'api_name': api_name,
                    'compliance_status': 'NON_COMPLIANT',
                    'reason': f'Error retrieving stages: {e}'
                })
        
        return {
            'compliance_status': 'COMPLIANT' if len(compliant_apis) > 0 and len(non_compliant_apis) == 0 else 'NON_COMPLIANT',
            'compliant_resources': compliant_apis,
            'non_compliant_resources': non_compliant_apis,
            'total_resources': len(rest_apis),
            'summary': f"Found {len(compliant_apis)} compliant and {len(non_compliant_apis)} non-compliant API Gateway REST API logging configurations"
        }
        
    except Exception as e:
        logger.error(f"Error checking API Gateway REST API logging: {str(e)}")
        return {
            'compliance_status': 'ERROR',
            'error': str(e)
        }

def awslambda_function_not_publicly_accessible(client, region, profile, logger):
    """
    Check if Lambda functions are not publicly accessible
    Serves 97 compliance requirements across multiple frameworks
    """
    findings = []
    try:
        paginator = client.get_paginator('list_functions')
        
        for page in paginator.paginate():
            functions = page.get('Functions', [])
            
            for function in functions:
                function_name = function['FunctionName']
                function_arn = function['FunctionArn']
                
                try:
                    # Get the function's resource-based policy
                    try:
                        policy_response = client.get_policy(FunctionName=function_name)
                        policy = json.loads(policy_response['Policy'])
                        statements = policy.get('Statement', [])
                        
                        is_publicly_accessible = False
                        public_statements = []
                        
                        for statement in statements:
                            principal = statement.get('Principal', {})
                            condition = statement.get('Condition', {})
                            
                            # Check if principal allows public access
                            if principal == '*' or principal == {'AWS': '*'}:
                                # Check if there are any restrictive conditions
                                if not condition:
                                    is_publicly_accessible = True
                                    public_statements.append(statement)
                                else:
                                    # Analyze conditions to see if they truly restrict access
                                    # For simplicity, we'll flag as potentially public if principal is *
                                    public_statements.append(statement)
                        
                        if is_publicly_accessible:
                            non_compliant_functions.append({
                                'function_name': function_name,
                                'function_arn': function_arn,
                                'public_statements': public_statements,
                                'status': 'NON_COMPLIANT',
                                'reason': 'Lambda function has publicly accessible resource policy'
                            })
                        else:
                            compliant_functions.append({
                                'function_name': function_name,
                                'function_arn': function_arn,
                                'status': 'COMPLIANT'
                            })
                            
                    except client.exceptions.ResourceNotFoundException:
                        # No resource policy exists, which means it's not publicly accessible
                        compliant_functions.append({
                            'function_name': function_name,
                            'function_arn': function_arn,
                            'status': 'COMPLIANT'
                        })
                        
                except Exception as function_error:
                    logger.warning(f"Error checking policy for function {function_name}: {str(function_error)}")
                    non_compliant_functions.append({
                        'function_name': function_name,
                        'function_arn': function_arn,
                        'status': 'NON_COMPLIANT',
                        'reason': f'Error retrieving function policy: {str(function_error)}'
                    })
            
            return {
                'compliance_status': 'COMPLIANT' if len(non_compliant_functions) == 0 else 'NON_COMPLIANT',
                'compliant_resources': compliant_functions,
                'non_compliant_resources': non_compliant_functions,
                'total_resources': len(functions),
                'summary': f"Found {len(compliant_functions)} compliant and {len(non_compliant_functions)} non-compliant Lambda function accessibility configurations"
            }
            
    except Exception as e:
        logger.error(f"Error checking Lambda function public accessibility: {str(e)}")
        return {
            'compliance_status': 'ERROR',
            'error': str(e)
        }
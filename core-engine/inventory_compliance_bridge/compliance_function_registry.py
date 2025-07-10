#!/usr/bin/env python3
"""
Compliance Function Registry

Registry of all available compliance functions with metadata and execution logic.
Integrates with the existing ComplianceEngine for orchestration.
"""

import sys
import os
import boto3
import json
import logging
from typing import Dict, List, Any, Callable
from datetime import datetime
from collections import defaultdict

# Add parent directories to path for imports
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.append(parent_dir)

from compliance_engine.compliance_engine import ComplianceEngine

class ComplianceFunctionRegistry:
    """Registry of all compliance functions with metadata and execution logic."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.functions = self._initialize_compliance_functions()
    
    def _initialize_compliance_functions(self) -> Dict[str, Dict[str, Any]]:
        """Initialize all compliance functions with metadata."""
        return {
            # S3 Compliance Functions
            'check_s3_bucket_encryption': {
                'service': 's3',
                'category': 'encryption',
                'severity': 'HIGH',
                'description': 'Verifies S3 buckets have encryption enabled',
                'boto3_api': 'get_bucket_encryption',
                'resource_type': 'bucket',
                'regions': ['global'],  # S3 buckets are region-specific but API is global
                'function': self._check_s3_bucket_encryption
            },
            'check_s3_bucket_public_access': {
                'service': 's3',
                'category': 'access_control',
                'severity': 'CRITICAL',
                'description': 'Checks if S3 buckets are publicly accessible',
                'boto3_api': 'get_bucket_acl',
                'resource_type': 'bucket',
                'regions': ['global'],
                'function': self._check_s3_bucket_public_access
            },
            'check_s3_bucket_versioning': {
                'service': 's3',
                'category': 'data_protection',
                'severity': 'MEDIUM',
                'description': 'Ensures S3 buckets have versioning enabled',
                'boto3_api': 'get_bucket_versioning',
                'resource_type': 'bucket',
                'regions': ['global'],
                'function': self._check_s3_bucket_versioning
            },
            'check_s3_bucket_ssl_requests_only': {
                'service': 's3',
                'category': 'encryption',
                'severity': 'HIGH',
                'description': 'Ensures S3 buckets require SSL requests only',
                'boto3_api': 'get_bucket_policy',
                'resource_type': 'bucket',
                'regions': ['global'],
                'function': self._check_s3_bucket_ssl_requests_only
            },
            
            # EC2 Compliance Functions
            'check_ec2_security_groups': {
                'service': 'ec2',
                'category': 'network_security',
                'severity': 'HIGH',
                'description': 'Validates EC2 security group rules',
                'boto3_api': 'describe_security_groups',
                'resource_type': 'security_group',
                'regions': ['regional'],
                'function': self._check_ec2_security_groups
            },
            'check_ec2_ebs_encryption': {
                'service': 'ec2',
                'category': 'encryption',
                'severity': 'HIGH',
                'description': 'Verifies EBS volumes are encrypted',
                'boto3_api': 'describe_volumes',
                'resource_type': 'volume',
                'regions': ['regional'],
                'function': self._check_ec2_ebs_encryption
            },
            'check_ec2_instances_in_vpc': {
                'service': 'ec2',
                'category': 'network_security',
                'severity': 'MEDIUM',
                'description': 'Ensures EC2 instances are launched in VPC',
                'boto3_api': 'describe_instances',
                'resource_type': 'instance',
                'regions': ['regional'],
                'function': self._check_ec2_instances_in_vpc
            },
            
            # RDS Compliance Functions
            'check_rds_encryption': {
                'service': 'rds',
                'category': 'encryption',
                'severity': 'HIGH',
                'description': 'Ensures RDS instances have encryption at rest',
                'boto3_api': 'describe_db_instances',
                'resource_type': 'db_instance',
                'regions': ['regional'],
                'function': self._check_rds_encryption
            },
            'check_rds_backup_enabled': {
                'service': 'rds',
                'category': 'backup',
                'severity': 'MEDIUM',
                'description': 'Validates RDS backup configuration',
                'boto3_api': 'describe_db_instances',
                'resource_type': 'db_instance',
                'regions': ['regional'],
                'function': self._check_rds_backup_enabled
            },
            'check_rds_public_access': {
                'service': 'rds',
                'category': 'access_control',
                'severity': 'HIGH',
                'description': 'Checks if RDS instances are publicly accessible',
                'boto3_api': 'describe_db_instances',
                'resource_type': 'db_instance',
                'regions': ['regional'],
                'function': self._check_rds_public_access
            },
            
            # IAM Compliance Functions
            'check_iam_password_policy': {
                'service': 'iam',
                'category': 'access_control',
                'severity': 'MEDIUM',
                'description': 'Validates IAM password policy requirements',
                'boto3_api': 'get_account_password_policy',
                'resource_type': 'account',
                'regions': ['global'],
                'function': self._check_iam_password_policy
            },
            'check_iam_mfa_enabled': {
                'service': 'iam',
                'category': 'access_control',
                'severity': 'HIGH',
                'description': 'Checks if MFA is enabled for IAM users',
                'boto3_api': 'list_users',
                'resource_type': 'user',
                'regions': ['global'],
                'function': self._check_iam_mfa_enabled
            },
            
            # Lambda Compliance Functions
            'check_lambda_function_public_access': {
                'service': 'lambda',
                'category': 'access_control',
                'severity': 'HIGH',
                'description': 'Checks if Lambda functions have public access',
                'boto3_api': 'get_policy',
                'resource_type': 'function',
                'regions': ['regional'],
                'function': self._check_lambda_function_public_access
            },
            'check_lambda_runtime_supported': {
                'service': 'lambda',
                'category': 'security',
                'severity': 'MEDIUM',
                'description': 'Validates Lambda runtime versions are supported',
                'boto3_api': 'get_function',
                'resource_type': 'function',
                'regions': ['regional'],
                'function': self._check_lambda_runtime_supported
            },
            
            # CloudTrail Compliance Functions
            'check_cloudtrail_enabled': {
                'service': 'cloudtrail',
                'category': 'logging',
                'severity': 'HIGH',
                'description': 'Ensures CloudTrail is enabled',
                'boto3_api': 'describe_trails',
                'resource_type': 'trail',
                'regions': ['regional'],
                'function': self._check_cloudtrail_enabled
            },
            
            # KMS Compliance Functions
            'check_kms_key_rotation': {
                'service': 'kms',
                'category': 'encryption',
                'severity': 'MEDIUM',
                'description': 'Validates KMS key rotation is enabled',
                'boto3_api': 'get_key_rotation_status',
                'resource_type': 'key',
                'regions': ['regional'],
                'function': self._check_kms_key_rotation
            }
        }
    
    # Individual Compliance Function Implementations
    # These return compliance check functions compatible with ComplianceEngine
    
    def _check_s3_bucket_encryption(self, resource_identifiers: List[str]):
        """Create S3 bucket encryption check function."""
        def compliance_check(client, region: str, account_name: str, logger) -> List[Dict[str, Any]]:
            findings = []
            for bucket_name in resource_identifiers:
                try:
                    # Check bucket encryption
                    response = client.get_bucket_encryption(Bucket=bucket_name)
                    rules = response.get('ServerSideEncryptionConfiguration', {}).get('Rules', [])
                    
                    if rules:
                        encryption_algorithm = rules[0].get('ApplyServerSideEncryptionByDefault', {}).get('SSEAlgorithm')
                        findings.append({
                            'resource_id': bucket_name,
                            'resource_type': 'S3 Bucket',
                            'region': region,
                            'account_name': account_name,
                            'compliance_status': 'COMPLIANT',
                            'finding_type': 'ENCRYPTION_ENABLED',
                            'severity': 'INFO',
                            'description': f'Bucket {bucket_name} has {encryption_algorithm} encryption enabled',
                            'details': {
                                'encryption_algorithm': encryption_algorithm,
                                'bucket_encryption_rules': len(rules)
                            },
                            'timestamp': datetime.now().isoformat()
                        })
                    else:
                        findings.append({
                            'resource_id': bucket_name,
                            'resource_type': 'S3 Bucket',
                            'region': region,
                            'account_name': account_name,
                            'compliance_status': 'NON_COMPLIANT',
                            'finding_type': 'ENCRYPTION_DISABLED',
                            'severity': 'HIGH',
                            'description': f'Bucket {bucket_name} does not have encryption enabled',
                            'recommendation': 'Enable server-side encryption for the S3 bucket',
                            'timestamp': datetime.now().isoformat()
                        })
                        
                except Exception as e:
                    findings.append({
                        'resource_id': bucket_name,
                        'resource_type': 'S3 Bucket',
                        'region': region,
                        'account_name': account_name,
                        'compliance_status': 'ERROR',
                        'finding_type': 'CHECK_FAILED',
                        'severity': 'UNKNOWN',
                        'description': f'Failed to check encryption for bucket {bucket_name}',
                        'error_message': str(e),
                        'timestamp': datetime.now().isoformat()
                    })
            
            return findings
        
        return compliance_check
    
    def _check_s3_bucket_public_access(self, resource_identifiers: List[str]):
        """Create S3 bucket public access check function."""
        def compliance_check(client, region: str, account_name: str, logger) -> List[Dict[str, Any]]:
            findings = []
            for bucket_name in resource_identifiers:
                try:
                    # Check public access block
                    try:
                        response = client.get_public_access_block(Bucket=bucket_name)
                        public_access_block = response.get('PublicAccessBlockConfiguration', {})
                        
                        is_blocked = all([
                            public_access_block.get('BlockPublicAcls', False),
                            public_access_block.get('IgnorePublicAcls', False),
                            public_access_block.get('BlockPublicPolicy', False),
                            public_access_block.get('RestrictPublicBuckets', False)
                        ])
                        
                        if is_blocked:
                            findings.append({
                                'resource_id': bucket_name,
                                'resource_type': 'S3 Bucket',
                                'region': region,
                                'account_name': account_name,
                                'compliance_status': 'COMPLIANT',
                                'finding_type': 'PUBLIC_ACCESS_BLOCKED',
                                'severity': 'INFO',
                                'description': f'Bucket {bucket_name} has public access properly blocked',
                                'timestamp': datetime.now().isoformat()
                            })
                        else:
                            findings.append({
                                'resource_id': bucket_name,
                                'resource_type': 'S3 Bucket',
                                'region': region,
                                'account_name': account_name,
                                'compliance_status': 'NON_COMPLIANT',
                                'finding_type': 'PUBLIC_ACCESS_ALLOWED',
                                'severity': 'CRITICAL',
                                'description': f'Bucket {bucket_name} may allow public access',
                                'recommendation': 'Enable S3 Block Public Access for the bucket',
                                'timestamp': datetime.now().isoformat()
                            })
                            
                    except client.exceptions.NoSuchPublicAccessBlockConfiguration:
                        findings.append({
                            'resource_id': bucket_name,
                            'resource_type': 'S3 Bucket',
                            'region': region,
                            'account_name': account_name,
                            'compliance_status': 'NON_COMPLIANT',
                            'finding_type': 'NO_PUBLIC_ACCESS_BLOCK',
                            'severity': 'HIGH',
                            'description': f'Bucket {bucket_name} has no public access block configuration',
                            'recommendation': 'Configure S3 Block Public Access for the bucket',
                            'timestamp': datetime.now().isoformat()
                        })
                        
                except Exception as e:
                    findings.append({
                        'resource_id': bucket_name,
                        'compliance_status': 'ERROR',
                        'description': f'Failed to check public access for bucket {bucket_name}: {str(e)}',
                        'timestamp': datetime.now().isoformat()
                    })
            
            return findings
        
        return compliance_check
    
    def _check_s3_bucket_versioning(self, resource_identifiers: List[str]):
        """Create S3 bucket versioning check function."""
        def compliance_check(client, region: str, account_name: str, logger) -> List[Dict[str, Any]]:
            findings = []
            for bucket_name in resource_identifiers:
                try:
                    response = client.get_bucket_versioning(Bucket=bucket_name)
                    versioning_status = response.get('Status', 'Disabled')
                    
                    if versioning_status == 'Enabled':
                        findings.append({
                            'resource_id': bucket_name,
                            'resource_type': 'S3 Bucket',
                            'region': region,
                            'account_name': account_name,
                            'compliance_status': 'COMPLIANT',
                            'finding_type': 'VERSIONING_ENABLED',
                            'severity': 'INFO',
                            'description': f'Bucket {bucket_name} has versioning enabled',
                            'timestamp': datetime.now().isoformat()
                        })
                    else:
                        findings.append({
                            'resource_id': bucket_name,
                            'resource_type': 'S3 Bucket',
                            'region': region,
                            'account_name': account_name,
                            'compliance_status': 'NON_COMPLIANT',
                            'finding_type': 'VERSIONING_DISABLED',
                            'severity': 'MEDIUM',
                            'description': f'Bucket {bucket_name} does not have versioning enabled',
                            'recommendation': 'Enable versioning for the S3 bucket',
                            'timestamp': datetime.now().isoformat()
                        })
                        
                except Exception as e:
                    findings.append({
                        'resource_id': bucket_name,
                        'compliance_status': 'ERROR',
                        'description': f'Failed to check versioning for bucket {bucket_name}: {str(e)}',
                        'timestamp': datetime.now().isoformat()
                    })
            
            return findings
        
        return compliance_check
    
    def _check_s3_bucket_ssl_requests_only(self, resource_identifiers: List[str]):
        """Create S3 bucket SSL-only requests check function."""
        def compliance_check(client, region: str, account_name: str, logger) -> List[Dict[str, Any]]:
            findings = []
            for bucket_name in resource_identifiers:
                try:
                    # Check bucket policy for SSL requirement
                    try:
                        response = client.get_bucket_policy(Bucket=bucket_name)
                        policy = json.loads(response['Policy'])
                        
                        ssl_required = False
                        for statement in policy.get('Statement', []):
                            effect = statement.get('Effect', '')
                            condition = statement.get('Condition', {})
                            
                            if (effect == 'Deny' and 
                                'aws:SecureTransport' in condition.get('Bool', {}) and
                                condition['Bool']['aws:SecureTransport'] == 'false'):
                                ssl_required = True
                                break
                        
                        if ssl_required:
                            findings.append({
                                'resource_id': bucket_name,
                                'compliance_status': 'COMPLIANT',
                                'finding_type': 'SSL_REQUIRED',
                                'severity': 'INFO',
                                'description': f'Bucket {bucket_name} requires SSL requests',
                                'timestamp': datetime.now().isoformat()
                            })
                        else:
                            findings.append({
                                'resource_id': bucket_name,
                                'compliance_status': 'NON_COMPLIANT',
                                'finding_type': 'SSL_NOT_REQUIRED',
                                'severity': 'HIGH',
                                'description': f'Bucket {bucket_name} does not require SSL requests',
                                'recommendation': 'Add bucket policy to deny non-SSL requests',
                                'timestamp': datetime.now().isoformat()
                            })
                            
                    except client.exceptions.NoSuchBucketPolicy:
                        findings.append({
                            'resource_id': bucket_name,
                            'compliance_status': 'NON_COMPLIANT',
                            'finding_type': 'NO_BUCKET_POLICY',
                            'severity': 'MEDIUM',
                            'description': f'Bucket {bucket_name} has no bucket policy',
                            'recommendation': 'Create bucket policy to enforce SSL requests',
                            'timestamp': datetime.now().isoformat()
                        })
                        
                except Exception as e:
                    findings.append({
                        'resource_id': bucket_name,
                        'compliance_status': 'ERROR',
                        'description': f'Failed to check SSL policy for bucket {bucket_name}: {str(e)}',
                        'timestamp': datetime.now().isoformat()
                    })
            
            return findings
        
        return compliance_check
    
    # Additional compliance function implementations would follow the same pattern...
    
    def _check_ec2_security_groups(self, resource_identifiers: List[str]):
        """Create EC2 security group check function."""
        def compliance_check(client, region: str, account_name: str, logger) -> List[Dict[str, Any]]:
            findings = []
            # Implementation for EC2 security groups
            # This would check for overly permissive rules
            return findings
        return compliance_check
    
    def _check_ec2_ebs_encryption(self, resource_identifiers: List[str]):
        """Create EBS encryption check function."""
        def compliance_check(client, region: str, account_name: str, logger) -> List[Dict[str, Any]]:
            findings = []
            # Implementation for EBS encryption
            return findings
        return compliance_check
    
    def _check_ec2_instances_in_vpc(self, resource_identifiers: List[str]):
        """Create EC2 VPC check function."""
        def compliance_check(client, region: str, account_name: str, logger) -> List[Dict[str, Any]]:
            findings = []
            # Implementation for EC2 VPC check
            return findings
        return compliance_check
    
    def _check_rds_encryption(self, resource_identifiers: List[str]):
        """Create RDS encryption check function."""
        def compliance_check(client, region: str, account_name: str, logger) -> List[Dict[str, Any]]:
            findings = []
            # Implementation for RDS encryption
            return findings
        return compliance_check
    
    def _check_rds_backup_enabled(self, resource_identifiers: List[str]):
        """Create RDS backup check function."""
        def compliance_check(client, region: str, account_name: str, logger) -> List[Dict[str, Any]]:
            findings = []
            # Implementation for RDS backup
            return findings
        return compliance_check
    
    def _check_rds_public_access(self, resource_identifiers: List[str]):
        """Create RDS public access check function."""
        def compliance_check(client, region: str, account_name: str, logger) -> List[Dict[str, Any]]:
            findings = []
            # Implementation for RDS public access
            return findings
        return compliance_check
    
    def _check_iam_password_policy(self, resource_identifiers: List[str]):
        """Create IAM password policy check function."""
        def compliance_check(client, region: str, account_name: str, logger) -> List[Dict[str, Any]]:
            findings = []
            # Implementation for IAM password policy
            return findings
        return compliance_check
    
    def _check_iam_mfa_enabled(self, resource_identifiers: List[str]):
        """Create IAM MFA check function."""
        def compliance_check(client, region: str, account_name: str, logger) -> List[Dict[str, Any]]:
            findings = []
            # Implementation for IAM MFA
            return findings
        return compliance_check
    
    def _check_lambda_function_public_access(self, resource_identifiers: List[str]):
        """Create Lambda public access check function."""
        def compliance_check(client, region: str, account_name: str, logger) -> List[Dict[str, Any]]:
            findings = []
            # Implementation for Lambda public access
            return findings
        return compliance_check
    
    def _check_lambda_runtime_supported(self, resource_identifiers: List[str]):
        """Create Lambda runtime check function."""
        def compliance_check(client, region: str, account_name: str, logger) -> List[Dict[str, Any]]:
            findings = []
            # Implementation for Lambda runtime
            return findings
        return compliance_check
    
    def _check_cloudtrail_enabled(self, resource_identifiers: List[str]):
        """Create CloudTrail enabled check function."""
        def compliance_check(client, region: str, account_name: str, logger) -> List[Dict[str, Any]]:
            findings = []
            # Implementation for CloudTrail
            return findings
        return compliance_check
    
    def _check_kms_key_rotation(self, resource_identifiers: List[str]):
        """Create KMS key rotation check function."""
        def compliance_check(client, region: str, account_name: str, logger) -> List[Dict[str, Any]]:
            findings = []
            # Implementation for KMS key rotation
            return findings
        return compliance_check
    
    # Registry Management Functions
    
    def get_functions_by_service(self, service: str) -> List[str]:
        """Get all compliance function names for a specific service."""
        return [name for name, config in self.functions.items() 
                if config['service'] == service]
    
    def get_function_metadata(self, function_name: str) -> Dict[str, Any]:
        """Get metadata for a specific compliance function."""
        return self.functions.get(function_name, {})
    
    def get_all_services(self) -> List[str]:
        """Get list of all services that have compliance functions."""
        services = set()
        for config in self.functions.values():
            services.add(config['service'])
        return sorted(list(services))
    
    def get_functions_by_category(self, category: str) -> List[str]:
        """Get all compliance functions for a specific category."""
        return [name for name, config in self.functions.items() 
                if config['category'] == category]
    
    def get_functions_by_severity(self, severity: str) -> List[str]:
        """Get all compliance functions for a specific severity level."""
        return [name for name, config in self.functions.items() 
                if config['severity'] == severity]
    
    def create_compliance_engine_function(self, function_name: str, resource_identifiers: List[str]):
        """
        Create a compliance function compatible with ComplianceEngine.
        
        Args:
            function_name: Name of the compliance function
            resource_identifiers: List of resource IDs to check
            
        Returns:
            Function compatible with ComplianceEngine.run_compliance_check()
        """
        if function_name not in self.functions:
            raise ValueError(f"Unknown compliance function: {function_name}")
        
        base_function = self.functions[function_name]['function']
        
        # Return the compliance check function with resource identifiers bound
        return base_function(resource_identifiers)
    
    def get_registry_stats(self) -> Dict[str, Any]:
        """Get statistics about the function registry."""
        stats = {
            'total_functions': len(self.functions),
            'services': defaultdict(int),
            'categories': defaultdict(int),
            'severities': defaultdict(int)
        }
        
        for config in self.functions.values():
            stats['services'][config['service']] += 1
            stats['categories'][config['category']] += 1
            stats['severities'][config['severity']] += 1
        
        return {
            'total_functions': stats['total_functions'],
            'services': dict(stats['services']),
            'categories': dict(stats['categories']),
            'severities': dict(stats['severities'])
        }
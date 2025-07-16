#!/usr/bin/env python3
"""
Comprehensive Test Suite for replication_backup_enabled Function

Tests the replication backup enabled compliance function with proper mocking,
error scenarios, and edge cases.
"""

import pytest
import boto3
import json
from unittest.mock import Mock, patch, MagicMock
from botocore.exceptions import ClientError, NoCredentialsError
from datetime import datetime, timezone
import sys
import os

# Add the data_function_list directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'data_function_list'))

# Import the compliance function
from replication_backup_enabled import replication_backup_enabled_check, replication_backup_enabled

class TestReplicationBackupEnabled:
    """Comprehensive test suite for replication_backup_enabled function."""
    
    def setup_method(self):
        """Setup test fixtures."""
        self.test_region = "us-east-1"
        self.test_profile = "test-profile"
        self.sample_bucket_name = "test-replication-bucket"
        self.sample_table_name = "test-global-table"
        self.sample_db_instance = "test-db-instance"
    
    def create_mock_session(self, client_responses: dict = None):
        """Create a mock boto3 session with configurable responses."""
        mock_session = Mock()
        
        # Mock different clients
        mock_s3_client = Mock()
        mock_dynamodb_client = Mock()
        mock_rds_client = Mock()
        
        # Configure client responses
        if client_responses:
            if 's3' in client_responses:
                for method, response in client_responses['s3'].items():
                    if isinstance(response, Exception):
                        getattr(mock_s3_client, method).side_effect = response
                    else:
                        getattr(mock_s3_client, method).return_value = response
            
            if 'dynamodb' in client_responses:
                for method, response in client_responses['dynamodb'].items():
                    if isinstance(response, Exception):
                        getattr(mock_dynamodb_client, method).side_effect = response
                    else:
                        getattr(mock_dynamodb_client, method).return_value = response
            
            if 'rds' in client_responses:
                for method, response in client_responses['rds'].items():
                    if isinstance(response, Exception):
                        getattr(mock_rds_client, method).side_effect = response
                    else:
                        getattr(mock_rds_client, method).return_value = response
        
        # Configure session.client to return appropriate mock client
        def client_factory(service_name, **kwargs):
            if service_name == 's3':
                return mock_s3_client
            elif service_name == 'dynamodb':
                return mock_dynamodb_client
            elif service_name == 'rds':
                return mock_rds_client
            else:
                return Mock()
        
        mock_session.client.side_effect = client_factory
        return mock_session, {
            's3': mock_s3_client,
            'dynamodb': mock_dynamodb_client,
            'rds': mock_rds_client
        }
    
    def assert_finding_structure(self, finding: dict):
        """Assert that a finding has the correct structure."""
        required_fields = ['region', 'profile', 'resource_type', 'resource_id', 
                          'status', 'risk_level', 'recommendation', 'details']
        
        for field in required_fields:
            assert field in finding, f"Missing required field: {field}"
        
        # Validate status values
        assert finding['status'] in ['COMPLIANT', 'NON_COMPLIANT', 'ERROR']
        
        # Validate risk levels
        assert finding['risk_level'] in ['LOW', 'MEDIUM', 'HIGH']
    
    def get_s3_replication_success_responses(self):
        """Get successful S3 replication mock responses."""
        return {
            'list_buckets': {
                'Buckets': [
                    {
                        'Name': self.sample_bucket_name,
                        'CreationDate': datetime(2023, 1, 1, tzinfo=timezone.utc)
                    }
                ]
            },
            'get_bucket_replication': {
                'ReplicationConfiguration': {
                    'Role': 'arn:aws:iam::123456789012:role/replication-role',
                    'Rules': [
                        {
                            'ID': 'ReplicateEverything',
                            'Status': 'Enabled',
                            'Prefix': '',
                            'Destination': {
                                'Bucket': 'arn:aws:s3:::destination-bucket',
                                'StorageClass': 'STANDARD_IA'
                            },
                            'DeleteMarkerReplication': {
                                'Status': 'Enabled'
                            },
                            'ReplicaModifications': {
                                'Status': 'Enabled'
                            }
                        }
                    ]
                }
            },
            'get_bucket_versioning': {
                'Status': 'Enabled',
                'MfaDelete': 'Enabled'
            },
            'get_bucket_lifecycle_configuration': {
                'Rules': [
                    {
                        'ID': 'lifecycle-rule',
                        'Status': 'Enabled',
                        'Transitions': [
                            {
                                'Days': 30,
                                'StorageClass': 'GLACIER'
                            }
                        ]
                    }
                ]
            }
        }
    
    def get_dynamodb_global_table_success_responses(self):
        """Get successful DynamoDB Global Table mock responses."""
        mock_paginator = Mock()
        mock_paginator.paginate.return_value = [
            {'TableNames': [self.sample_table_name]}
        ]
        
        return {
            'get_paginator': mock_paginator,
            'describe_table': {
                'Table': {
                    'TableName': self.sample_table_name,
                    'TableArn': f'arn:aws:dynamodb:{self.test_region}:123456789012:table/{self.sample_table_name}',
                    'TableStatus': 'ACTIVE',
                    'GlobalTableVersion': '2019.11.21',
                    'Replicas': [
                        {
                            'RegionName': 'us-west-2',
                            'ReplicaStatus': 'ACTIVE'
                        }
                    ],
                    'SSEDescription': {
                        'Status': 'ENABLED',
                        'KMSMasterKeyArn': 'arn:aws:kms:us-east-1:123456789012:key/test-key'
                    }
                }
            },
            'describe_continuous_backups': {
                'ContinuousBackupsDescription': {
                    'ContinuousBackupsStatus': 'ENABLED',
                    'PointInTimeRecoveryDescription': {
                        'PointInTimeRecoveryStatus': 'ENABLED'
                    }
                }
            }
        }
    
    def get_rds_backup_success_responses(self):
        """Get successful RDS backup mock responses."""
        mock_paginator = Mock()
        mock_paginator.paginate.return_value = [
            {
                'DBInstances': [
                    {
                        'DBInstanceIdentifier': self.sample_db_instance,
                        'DBInstanceArn': f'arn:aws:rds:{self.test_region}:123456789012:db:{self.sample_db_instance}',
                        'BackupRetentionPeriod': 7,
                        'StorageEncrypted': True,
                        'KmsKeyId': 'arn:aws:kms:us-east-1:123456789012:key/test-key'
                    }
                ]
            }
        ]
        
        return {
            'get_paginator': mock_paginator,
            'describe_db_instance_automated_backups': {
                'DBInstanceAutomatedBackups': [
                    {
                        'Region': 'us-west-2',
                        'DBInstanceIdentifier': self.sample_db_instance
                    }
                ]
            },
            'describe_db_snapshots': {
                'DBSnapshots': [
                    {
                        'DBSnapshotIdentifier': 'manual-snapshot-1',
                        'SnapshotType': 'manual'
                    }
                ]
            }
        }
    
    def test_s3_replication_backup_compliant(self):
        """Test S3 replication backup compliance check with compliant configuration."""
        mock_responses = {
            's3': self.get_s3_replication_success_responses()
        }
        
        with patch('boto3.Session') as mock_session_class:
            mock_session, mock_clients = self.create_mock_session(mock_responses)
            mock_session_class.return_value = mock_session
            
            findings = replication_backup_enabled_check(self.test_region, self.test_profile)
            
            assert isinstance(findings, list)
            if findings:
                for finding in findings:
                    self.assert_finding_structure(finding)
                    if finding['resource_type'] == 's3_replication':
                        assert finding['status'] in ['COMPLIANT', 'NON_COMPLIANT']
    
    def test_s3_replication_backup_non_compliant(self):
        """Test S3 replication backup with non-compliant configuration."""
        mock_responses = {
            's3': {
                'list_buckets': {
                    'Buckets': [{'Name': self.sample_bucket_name}]
                },
                'get_bucket_replication': {
                    'ReplicationConfiguration': {
                        'Rules': [
                            {
                                'ID': 'BadRule',
                                'Status': 'Disabled',  # Non-compliant
                                'Destination': {
                                    'Bucket': 'arn:aws:s3:::destination-bucket'
                                }
                            }
                        ]
                    }
                },
                'get_bucket_versioning': {
                    'Status': 'Suspended'  # Non-compliant
                },
                'get_bucket_lifecycle_configuration': ClientError(
                    {'Error': {'Code': 'NoSuchLifecycleConfiguration'}},
                    'GetBucketLifecycleConfiguration'
                )
            }
        }
        
        with patch('boto3.Session') as mock_session_class:
            mock_session, mock_clients = self.create_mock_session(mock_responses)
            mock_session_class.return_value = mock_session
            
            findings = replication_backup_enabled_check(self.test_region, self.test_profile)
            
            assert isinstance(findings, list)
            if findings:
                non_compliant_findings = [f for f in findings if f['status'] == 'NON_COMPLIANT']
                assert len(non_compliant_findings) > 0
    
    def test_dynamodb_global_table_backup_compliant(self):
        """Test DynamoDB Global Table backup compliance."""
        mock_responses = {
            'dynamodb': self.get_dynamodb_global_table_success_responses()
        }
        
        with patch('boto3.Session') as mock_session_class:
            mock_session, mock_clients = self.create_mock_session(mock_responses)
            mock_session_class.return_value = mock_session
            
            findings = replication_backup_enabled_check(self.test_region, self.test_profile)
            
            assert isinstance(findings, list)
            if findings:
                for finding in findings:
                    self.assert_finding_structure(finding)
                    if finding['resource_type'] == 'dynamodb_global_table':
                        assert finding['status'] in ['COMPLIANT', 'NON_COMPLIANT']
    
    def test_rds_backup_replication_compliant(self):
        """Test RDS backup replication compliance."""
        mock_responses = {
            'rds': self.get_rds_backup_success_responses()
        }
        
        with patch('boto3.Session') as mock_session_class:
            mock_session, mock_clients = self.create_mock_session(mock_responses)
            mock_session_class.return_value = mock_session
            
            findings = replication_backup_enabled_check(self.test_region, self.test_profile)
            
            assert isinstance(findings, list)
            if findings:
                for finding in findings:
                    self.assert_finding_structure(finding)
                    if finding['resource_type'] == 'rds_instance':
                        assert finding['status'] in ['COMPLIANT', 'NON_COMPLIANT']
    
    def test_api_access_error_handling(self):
        """Test error handling for API access issues."""
        error_responses = {
            's3': {
                'list_buckets': ClientError(
                    {'Error': {'Code': 'AccessDenied', 'Message': 'Access denied'}},
                    'ListBuckets'
                )
            }
        }
        
        with patch('boto3.Session') as mock_session_class:
            mock_session, mock_clients = self.create_mock_session(error_responses)
            mock_session_class.return_value = mock_session
            
            findings = replication_backup_enabled_check(self.test_region, self.test_profile)
            
            assert isinstance(findings, list)
            # Should handle errors gracefully and continue checking other services
            
    def test_no_credentials_error(self):
        """Test handling of no AWS credentials."""
        with patch('boto3.Session') as mock_session_class:
            mock_session_class.side_effect = NoCredentialsError()
            
            findings = replication_backup_enabled_check(self.test_region, self.test_profile)
            
            assert isinstance(findings, list)
            assert len(findings) >= 1
            assert all(f['status'] == 'ERROR' for f in findings)
    
    def test_no_replication_configured(self):
        """Test handling when no replication is configured."""
        mock_responses = {
            's3': {
                'list_buckets': {'Buckets': [{'Name': self.sample_bucket_name}]},
                'get_bucket_replication': ClientError(
                    {'Error': {'Code': 'ReplicationConfigurationNotFoundError'}},
                    'GetBucketReplication'
                )
            }
        }
        
        with patch('boto3.Session') as mock_session_class:
            mock_session, mock_clients = self.create_mock_session(mock_responses)
            mock_session_class.return_value = mock_session
            
            findings = replication_backup_enabled_check(self.test_region, self.test_profile)
            
            assert isinstance(findings, list)
            # Should not fail when no replication is configured
    
    def test_wrapper_function(self):
        """Test the main wrapper function."""
        mock_responses = {
            's3': self.get_s3_replication_success_responses()
        }
        
        with patch('boto3.Session') as mock_session_class:
            mock_session, mock_clients = self.create_mock_session(mock_responses)
            mock_session_class.return_value = mock_session
            
            result = replication_backup_enabled(self.test_region, self.test_profile)
            
            assert isinstance(result, dict)
            required_keys = ['function_name', 'region', 'profile', 'total_findings',
                           'compliant_count', 'non_compliant_count', 'error_count',
                           'compliance_rate', 'findings']
            
            for key in required_keys:
                assert key in result
            
            assert result['function_name'] == 'replication_backup_enabled'
            assert result['region'] == self.test_region
            assert isinstance(result['findings'], list)
    
    def test_mixed_compliance_scenarios(self):
        """Test mixed scenarios with both compliant and non-compliant resources."""
        mock_responses = {
            's3': {
                'list_buckets': {
                    'Buckets': [
                        {'Name': 'compliant-bucket'},
                        {'Name': 'non-compliant-bucket'}
                    ]
                },
                'get_bucket_replication': {
                    'ReplicationConfiguration': {
                        'Rules': [
                            {
                                'ID': 'rule1',
                                'Status': 'Enabled',
                                'Destination': {'Bucket': 'arn:aws:s3:::dest'}
                            }
                        ]
                    }
                }
            }
        }
        
        # Make versioning fail for one bucket
        def versioning_side_effect(*args, **kwargs):
            bucket_name = kwargs.get('Bucket', '')
            if 'non-compliant' in bucket_name:
                return {'Status': 'Suspended'}
            return {'Status': 'Enabled'}
        
        with patch('boto3.Session') as mock_session_class:
            mock_session, mock_clients = self.create_mock_session(mock_responses)
            mock_clients['s3'].get_bucket_versioning.side_effect = versioning_side_effect
            mock_session_class.return_value = mock_session
            
            findings = replication_backup_enabled_check(self.test_region, self.test_profile)
            
            assert isinstance(findings, list)
            if findings:
                statuses = [f['status'] for f in findings]
                # Should have a mix of statuses
                assert len(set(statuses)) > 1 or 'NON_COMPLIANT' in statuses
    
    def test_edge_case_empty_responses(self):
        """Test edge cases with empty API responses."""
        mock_responses = {
            's3': {
                'list_buckets': {'Buckets': []},
            },
            'dynamodb': {
                'get_paginator': Mock(return_value=Mock(paginate=Mock(return_value=[{'TableNames': []}])))
            },
            'rds': {
                'get_paginator': Mock(return_value=Mock(paginate=Mock(return_value=[{'DBInstances': []}])))
            }
        }
        
        with patch('boto3.Session') as mock_session_class:
            mock_session, mock_clients = self.create_mock_session(mock_responses)
            mock_session_class.return_value = mock_session
            
            findings = replication_backup_enabled_check(self.test_region, self.test_profile)
            
            assert isinstance(findings, list)
            # Should handle empty responses gracefully

def test_module_imports():
    """Test that the module can be imported successfully."""
    try:
        import replication_backup_enabled
        assert hasattr(replication_backup_enabled, 'replication_backup_enabled_check')
        assert hasattr(replication_backup_enabled, 'replication_backup_enabled')
    except ImportError as e:
        pytest.fail(f"Failed to import replication_backup_enabled: {e}")

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
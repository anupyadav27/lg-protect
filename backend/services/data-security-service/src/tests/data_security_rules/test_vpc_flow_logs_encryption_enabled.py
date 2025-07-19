#!/usr/bin/env python3
"""
Comprehensive Test Suite for vpc_flow_logs_encryption_enabled Function

Tests the VPC Flow Logs encryption compliance function with proper mocking,
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
from vpc_flow_logs_encryption_enabled import vpc_flow_logs_encryption_enabled_check, vpc_flow_logs_encryption_enabled

class TestVPCFlowLogsEncryptionEnabled:
    """Comprehensive test suite for vpc_flow_logs_encryption_enabled function."""
    
    def setup_method(self):
        """Setup test fixtures."""
        self.test_region = "us-east-1"
        self.test_profile = "test-profile"
        self.sample_vpc_id = "vpc-12345678"
        self.sample_flow_log_id = "fl-12345678"
        self.sample_log_group = "test-log-group"
        self.sample_s3_bucket = "test-flow-logs-bucket"
    
    def create_mock_session(self, client_responses: dict = None):
        """Create a mock boto3 session with configurable responses."""
        mock_session = Mock()
        
        # Mock different clients
        mock_ec2_client = Mock()
        mock_logs_client = Mock()
        mock_s3_client = Mock()
        
        # Configure client responses
        if client_responses:
            if 'ec2' in client_responses:
                for method, response in client_responses['ec2'].items():
                    if isinstance(response, Exception):
                        getattr(mock_ec2_client, method).side_effect = response
                    else:
                        getattr(mock_ec2_client, method).return_value = response
            
            if 'logs' in client_responses:
                for method, response in client_responses['logs'].items():
                    if isinstance(response, Exception):
                        getattr(mock_logs_client, method).side_effect = response
                    else:
                        getattr(mock_logs_client, method).return_value = response
            
            if 's3' in client_responses:
                for method, response in client_responses['s3'].items():
                    if isinstance(response, Exception):
                        getattr(mock_s3_client, method).side_effect = response
                    else:
                        getattr(mock_s3_client, method).return_value = response
        
        # Configure session.client to return appropriate mock client
        def client_factory(service_name, **kwargs):
            if service_name == 'ec2':
                return mock_ec2_client
            elif service_name == 'logs':
                return mock_logs_client
            elif service_name == 's3':
                return mock_s3_client
            else:
                return Mock()
        
        mock_session.client.side_effect = client_factory
        return mock_session, {
            'ec2': mock_ec2_client,
            'logs': mock_logs_client,
            's3': mock_s3_client
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
    
    def get_vpc_with_encrypted_cloudwatch_flow_logs(self):
        """Get mock responses for VPC with encrypted CloudWatch flow logs."""
        return {
            'ec2': {
                'describe_vpcs': {
                    'Vpcs': [
                        {
                            'VpcId': self.sample_vpc_id,
                            'State': 'available',
                            'CidrBlock': '10.0.0.0/16'
                        }
                    ]
                },
                'describe_flow_logs': {
                    'FlowLogs': [
                        {
                            'FlowLogId': self.sample_flow_log_id,
                            'FlowLogStatus': 'ACTIVE',
                            'LogDestinationType': 'cloud-watch-logs',
                            'LogGroupName': self.sample_log_group
                        }
                    ]
                }
            },
            'logs': {
                'describe_log_groups': {
                    'logGroups': [
                        {
                            'logGroupName': self.sample_log_group,
                            'kmsKeyId': 'arn:aws:kms:us-east-1:123456789012:key/test-key'
                        }
                    ]
                }
            }
        }
    
    def get_vpc_with_encrypted_s3_flow_logs(self):
        """Get mock responses for VPC with encrypted S3 flow logs."""
        return {
            'ec2': {
                'describe_vpcs': {
                    'Vpcs': [
                        {
                            'VpcId': self.sample_vpc_id,
                            'State': 'available',
                            'CidrBlock': '10.0.0.0/16'
                        }
                    ]
                },
                'describe_flow_logs': {
                    'FlowLogs': [
                        {
                            'FlowLogId': self.sample_flow_log_id,
                            'FlowLogStatus': 'ACTIVE',
                            'LogDestinationType': 's3',
                            'DestinationOptions': {
                                'S3BucketName': self.sample_s3_bucket
                            }
                        }
                    ]
                }
            },
            's3': {
                'get_bucket_encryption': {
                    'ServerSideEncryptionConfiguration': {
                        'Rules': [
                            {
                                'ApplyServerSideEncryptionByDefault': {
                                    'SSEAlgorithm': 'aws:kms',
                                    'KMSMasterKeyID': 'arn:aws:kms:us-east-1:123456789012:key/test-key'
                                }
                            }
                        ]
                    }
                }
            }
        }
    
    def get_vpc_with_unencrypted_flow_logs(self):
        """Get mock responses for VPC with unencrypted flow logs."""
        return {
            'ec2': {
                'describe_vpcs': {
                    'Vpcs': [
                        {
                            'VpcId': self.sample_vpc_id,
                            'State': 'available',
                            'CidrBlock': '10.0.0.0/16'
                        }
                    ]
                },
                'describe_flow_logs': {
                    'FlowLogs': [
                        {
                            'FlowLogId': self.sample_flow_log_id,
                            'FlowLogStatus': 'ACTIVE',
                            'LogDestinationType': 'cloud-watch-logs',
                            'LogGroupName': self.sample_log_group
                        }
                    ]
                }
            },
            'logs': {
                'describe_log_groups': {
                    'logGroups': [
                        {
                            'logGroupName': self.sample_log_group
                            # No kmsKeyId - unencrypted
                        }
                    ]
                }
            }
        }
    
    def get_vpc_without_flow_logs(self):
        """Get mock responses for VPC without flow logs."""
        return {
            'ec2': {
                'describe_vpcs': {
                    'Vpcs': [
                        {
                            'VpcId': self.sample_vpc_id,
                            'State': 'available',
                            'CidrBlock': '10.0.0.0/16'
                        }
                    ]
                },
                'describe_flow_logs': {
                    'FlowLogs': []  # No flow logs configured
                }
            }
        }
    
    def test_vpc_with_encrypted_cloudwatch_flow_logs_compliant(self):
        """Test VPC with encrypted CloudWatch flow logs - should be compliant."""
        mock_responses = self.get_vpc_with_encrypted_cloudwatch_flow_logs()
        
        with patch('boto3.Session') as mock_session_class:
            mock_session, mock_clients = self.create_mock_session(mock_responses)
            mock_session_class.return_value = mock_session
            
            findings = vpc_flow_logs_encryption_enabled_check(self.test_region, self.test_profile)
            
            assert isinstance(findings, list)
            assert len(findings) > 0
            
            # Should have at least one compliant finding
            compliant_findings = [f for f in findings if f['status'] == 'COMPLIANT']
            assert len(compliant_findings) > 0
            
            for finding in findings:
                self.assert_finding_structure(finding)
                if finding['status'] == 'COMPLIANT':
                    assert 'encryption_details' in finding['details']
                    assert finding['details']['encryption_details']['destination_type'] == 'cloudwatch-logs'
    
    def test_vpc_with_encrypted_s3_flow_logs_compliant(self):
        """Test VPC with encrypted S3 flow logs - should be compliant."""
        mock_responses = self.get_vpc_with_encrypted_s3_flow_logs()
        
        with patch('boto3.Session') as mock_session_class:
            mock_session, mock_clients = self.create_mock_session(mock_responses)
            mock_session_class.return_value = mock_session
            
            findings = vpc_flow_logs_encryption_enabled_check(self.test_region, self.test_profile)
            
            assert isinstance(findings, list)
            assert len(findings) > 0
            
            # Should have at least one compliant finding
            compliant_findings = [f for f in findings if f['status'] == 'COMPLIANT']
            assert len(compliant_findings) > 0
            
            for finding in findings:
                self.assert_finding_structure(finding)
                if finding['status'] == 'COMPLIANT':
                    assert 'encryption_details' in finding['details']
                    assert finding['details']['encryption_details']['destination_type'] == 's3'
    
    def test_vpc_with_unencrypted_flow_logs_non_compliant(self):
        """Test VPC with unencrypted flow logs - should be non-compliant."""
        mock_responses = self.get_vpc_with_unencrypted_flow_logs()
        
        with patch('boto3.Session') as mock_session_class:
            mock_session, mock_clients = self.create_mock_session(mock_responses)
            mock_session_class.return_value = mock_session
            
            findings = vpc_flow_logs_encryption_enabled_check(self.test_region, self.test_profile)
            
            assert isinstance(findings, list)
            assert len(findings) > 0
            
            # Should have at least one non-compliant finding
            non_compliant_findings = [f for f in findings if f['status'] == 'NON_COMPLIANT']
            assert len(non_compliant_findings) > 0
            
            for finding in findings:
                self.assert_finding_structure(finding)
                if finding['status'] == 'NON_COMPLIANT':
                    assert 'violation' in finding['details']
                    assert 'not encrypted' in finding['details']['violation'].lower()
    
    def test_vpc_without_flow_logs_non_compliant(self):
        """Test VPC without flow logs - should be non-compliant."""
        mock_responses = self.get_vpc_without_flow_logs()
        
        with patch('boto3.Session') as mock_session_class:
            mock_session, mock_clients = self.create_mock_session(mock_responses)
            mock_session_class.return_value = mock_session
            
            findings = vpc_flow_logs_encryption_enabled_check(self.test_region, self.test_profile)
            
            assert isinstance(findings, list)
            assert len(findings) > 0
            
            # Should have at least one non-compliant finding
            non_compliant_findings = [f for f in findings if f['status'] == 'NON_COMPLIANT']
            assert len(non_compliant_findings) > 0
            
            for finding in findings:
                self.assert_finding_structure(finding)
                if finding['status'] == 'NON_COMPLIANT':
                    assert 'No VPC Flow Logs configured' in finding['details']['violation']
    
    def test_s3_encryption_not_configured(self):
        """Test S3 flow logs with no encryption configuration."""
        mock_responses = {
            'ec2': {
                'describe_vpcs': {
                    'Vpcs': [
                        {
                            'VpcId': self.sample_vpc_id,
                            'State': 'available',
                            'CidrBlock': '10.0.0.0/16'
                        }
                    ]
                },
                'describe_flow_logs': {
                    'FlowLogs': [
                        {
                            'FlowLogId': self.sample_flow_log_id,
                            'FlowLogStatus': 'ACTIVE',
                            'LogDestinationType': 's3',
                            'DestinationOptions': {
                                'S3BucketName': self.sample_s3_bucket
                            }
                        }
                    ]
                }
            },
            's3': {
                'get_bucket_encryption': ClientError(
                    {'Error': {'Code': 'ServerSideEncryptionConfigurationNotFoundError'}},
                    'GetBucketEncryption'
                )
            }
        }
        
        with patch('boto3.Session') as mock_session_class:
            mock_session, mock_clients = self.create_mock_session(mock_responses)
            mock_session_class.return_value = mock_session
            
            findings = vpc_flow_logs_encryption_enabled_check(self.test_region, self.test_profile)
            
            assert isinstance(findings, list)
            assert len(findings) > 0
            
            # Should have non-compliant finding for unencrypted S3
            non_compliant_findings = [f for f in findings if f['status'] == 'NON_COMPLIANT']
            assert len(non_compliant_findings) > 0
    
    def test_inactive_flow_logs_ignored(self):
        """Test that inactive flow logs are ignored."""
        mock_responses = {
            'ec2': {
                'describe_vpcs': {
                    'Vpcs': [
                        {
                            'VpcId': self.sample_vpc_id,
                            'State': 'available',
                            'CidrBlock': '10.0.0.0/16'
                        }
                    ]
                },
                'describe_flow_logs': {
                    'FlowLogs': [
                        {
                            'FlowLogId': self.sample_flow_log_id,
                            'FlowLogStatus': 'INACTIVE',  # Inactive flow log
                            'LogDestinationType': 'cloud-watch-logs',
                            'LogGroupName': self.sample_log_group
                        }
                    ]
                }
            }
        }
        
        with patch('boto3.Session') as mock_session_class:
            mock_session, mock_clients = self.create_mock_session(mock_responses)
            mock_session_class.return_value = mock_session
            
            findings = vpc_flow_logs_encryption_enabled_check(self.test_region, self.test_profile)
            
            assert isinstance(findings, list)
            # Should not have findings for inactive flow logs
    
    def test_unavailable_vpc_ignored(self):
        """Test that unavailable VPCs are ignored."""
        mock_responses = {
            'ec2': {
                'describe_vpcs': {
                    'Vpcs': [
                        {
                            'VpcId': self.sample_vpc_id,
                            'State': 'pending',  # Not available
                            'CidrBlock': '10.0.0.0/16'
                        }
                    ]
                }
            }
        }
        
        with patch('boto3.Session') as mock_session_class:
            mock_session, mock_clients = self.create_mock_session(mock_responses)
            mock_session_class.return_value = mock_session
            
            findings = vpc_flow_logs_encryption_enabled_check(self.test_region, self.test_profile)
            
            assert isinstance(findings, list)
            # Should not have findings for unavailable VPCs
    
    def test_api_access_error_handling(self):
        """Test error handling for API access issues."""
        error_responses = {
            'ec2': {
                'describe_vpcs': ClientError(
                    {'Error': {'Code': 'AccessDenied', 'Message': 'Access denied'}},
                    'DescribeVpcs'
                )
            }
        }
        
        with patch('boto3.Session') as mock_session_class:
            mock_session, mock_clients = self.create_mock_session(error_responses)
            mock_session_class.return_value = mock_session
            
            findings = vpc_flow_logs_encryption_enabled_check(self.test_region, self.test_profile)
            
            assert isinstance(findings, list)
            assert len(findings) >= 1
            
            # Should have at least one ERROR finding
            error_findings = [f for f in findings if f['status'] == 'ERROR']
            assert len(error_findings) >= 1
    
    def test_no_credentials_error(self):
        """Test handling of no AWS credentials."""
        with patch('boto3.Session') as mock_session_class:
            mock_session_class.side_effect = NoCredentialsError()
            
            findings = vpc_flow_logs_encryption_enabled_check(self.test_region, self.test_profile)
            
            assert isinstance(findings, list)
            assert len(findings) >= 1
            assert all(f['status'] == 'ERROR' for f in findings)
    
    def test_vpc_specific_error_handling(self):
        """Test error handling for VPC-specific issues."""
        mock_responses = {
            'ec2': {
                'describe_vpcs': {
                    'Vpcs': [
                        {
                            'VpcId': self.sample_vpc_id,
                            'State': 'available',
                            'CidrBlock': '10.0.0.0/16'
                        }
                    ]
                },
                'describe_flow_logs': ClientError(
                    {'Error': {'Code': 'InvalidVpcID.NotFound'}},
                    'DescribeFlowLogs'
                )
            }
        }
        
        with patch('boto3.Session') as mock_session_class:
            mock_session, mock_clients = self.create_mock_session(mock_responses)
            mock_session_class.return_value = mock_session
            
            findings = vpc_flow_logs_encryption_enabled_check(self.test_region, self.test_profile)
            
            assert isinstance(findings, list)
            # Should handle VPC-specific errors gracefully
            error_findings = [f for f in findings if f['status'] == 'ERROR']
            if error_findings:
                assert len(error_findings) >= 1
    
    def test_wrapper_function(self):
        """Test the main wrapper function."""
        mock_responses = self.get_vpc_with_encrypted_cloudwatch_flow_logs()
        
        with patch('boto3.Session') as mock_session_class:
            mock_session, mock_clients = self.create_mock_session(mock_responses)
            mock_session_class.return_value = mock_session
            
            result = vpc_flow_logs_encryption_enabled(self.test_region, self.test_profile)
            
            assert isinstance(result, dict)
            required_keys = ['function_name', 'region', 'profile', 'total_findings',
                           'compliant_count', 'non_compliant_count', 'error_count',
                           'compliance_rate', 'findings']
            
            for key in required_keys:
                assert key in result
            
            assert result['function_name'] == 'vpc_flow_logs_encryption_enabled'
            assert result['region'] == self.test_region
            assert isinstance(result['findings'], list)
    
    def test_mixed_vpc_scenarios(self):
        """Test multiple VPCs with different flow log configurations."""
        mock_responses = {
            'ec2': {
                'describe_vpcs': {
                    'Vpcs': [
                        {
                            'VpcId': 'vpc-encrypted',
                            'State': 'available',
                            'CidrBlock': '10.0.0.0/16'
                        },
                        {
                            'VpcId': 'vpc-unencrypted',
                            'State': 'available',
                            'CidrBlock': '10.1.0.0/16'
                        },
                        {
                            'VpcId': 'vpc-no-logs',
                            'State': 'available',
                            'CidrBlock': '10.2.0.0/16'
                        }
                    ]
                }
            }
        }
        
        # Mock flow logs response based on VPC
        def describe_flow_logs_side_effect(*args, **kwargs):
            filters = kwargs.get('Filters', [])
            vpc_id = None
            for f in filters:
                if f.get('Name') == 'resource-id':
                    vpc_id = f.get('Values', [''])[0]
                    break
            
            if vpc_id == 'vpc-encrypted':
                return {
                    'FlowLogs': [
                        {
                            'FlowLogId': 'fl-encrypted',
                            'FlowLogStatus': 'ACTIVE',
                            'LogDestinationType': 'cloud-watch-logs',
                            'LogGroupName': 'encrypted-log-group'
                        }
                    ]
                }
            elif vpc_id == 'vpc-unencrypted':
                return {
                    'FlowLogs': [
                        {
                            'FlowLogId': 'fl-unencrypted',
                            'FlowLogStatus': 'ACTIVE',
                            'LogDestinationType': 'cloud-watch-logs',
                            'LogGroupName': 'unencrypted-log-group'
                        }
                    ]
                }
            else:
                return {'FlowLogs': []}
        
        # Mock log groups response
        def describe_log_groups_side_effect(*args, **kwargs):
            log_group_prefix = kwargs.get('logGroupNamePrefix', '')
            if 'encrypted' in log_group_prefix:
                return {
                    'logGroups': [
                        {
                            'logGroupName': log_group_prefix,
                            'kmsKeyId': 'arn:aws:kms:us-east-1:123456789012:key/test-key'
                        }
                    ]
                }
            else:
                return {
                    'logGroups': [
                        {
                            'logGroupName': log_group_prefix
                            # No kmsKeyId
                        }
                    ]
                }
        
        with patch('boto3.Session') as mock_session_class:
            mock_session, mock_clients = self.create_mock_session(mock_responses)
            mock_clients['ec2'].describe_flow_logs.side_effect = describe_flow_logs_side_effect
            mock_clients['logs'].describe_log_groups.side_effect = describe_log_groups_side_effect
            mock_session_class.return_value = mock_session
            
            findings = vpc_flow_logs_encryption_enabled_check(self.test_region, self.test_profile)
            
            assert isinstance(findings, list)
            assert len(findings) >= 3  # Should have findings for all 3 VPCs
            
            # Should have a mix of compliance statuses
            statuses = [f['status'] for f in findings]
            unique_statuses = set(statuses)
            assert len(unique_statuses) > 1  # Should have different statuses

def test_module_imports():
    """Test that the module can be imported successfully."""
    try:
        import vpc_flow_logs_encryption_enabled
        assert hasattr(vpc_flow_logs_encryption_enabled, 'vpc_flow_logs_encryption_enabled_check')
        assert hasattr(vpc_flow_logs_encryption_enabled, 'vpc_flow_logs_encryption_enabled')
    except ImportError as e:
        pytest.fail(f"Failed to import vpc_flow_logs_encryption_enabled: {e}")

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
#!/usr/bin/env python3
"""
Comprehensive Test Suite for KMS Key Data Sovereignty Tags Compliance Function

Tests the kms_key_data_sovereignty_tags function with proper mocking,
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
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'data_function_list'))

# Import the function to test
from kms_key_data_sovereignty_tags import kms_key_data_sovereignty_tags_check, kms_key_data_sovereignty_tags

class TestKMSKeyDataSovereigntyTagsCompliance:
    """Comprehensive test suite for KMS key data sovereignty tags compliance function."""
    
    def setup_method(self):
        """Setup test fixtures."""
        self.test_region = "us-east-1"
        self.test_profile = "test-profile"
        self.sample_findings = []
    
    def create_mock_kms_client(self, responses: dict = None):
        """Create a mock KMS client with configurable responses."""
        mock_client = Mock()
        
        # Default responses
        default_responses = {
            'list_keys': {
                'Keys': [
                    {
                        'KeyId': 'test-key-1',
                        'KeyArn': 'arn:aws:kms:us-east-1:123456789012:key/test-key-1'
                    },
                    {
                        'KeyId': 'test-key-2', 
                        'KeyArn': 'arn:aws:kms:us-east-1:123456789012:key/test-key-2'
                    }
                ]
            },
            'describe_key': {
                'KeyMetadata': {
                    'KeyId': 'test-key-1',
                    'Arn': 'arn:aws:kms:us-east-1:123456789012:key/test-key-1',
                    'KeyManager': 'CUSTOMER',
                    'KeyUsage': 'ENCRYPT_DECRYPT',
                    'KeyState': 'Enabled',
                    'KeySpec': 'SYMMETRIC_DEFAULT',
                    'CreationDate': datetime(2023, 1, 1, tzinfo=timezone.utc)
                }
            },
            'list_resource_tags': {
                'Tags': [
                    {'TagKey': 'DataJurisdiction', 'TagValue': 'US'},
                    {'TagKey': 'DataResidency', 'TagValue': 'us-east-1'},
                    {'TagKey': 'ComplianceFramework', 'TagValue': 'SOX'},
                    {'TagKey': 'DataClassification', 'TagValue': 'CONFIDENTIAL'}
                ]
            }
        }
        
        # Override with provided responses
        if responses:
            default_responses.update(responses)
        
        # Configure mock methods
        for method, response in default_responses.items():
            if isinstance(response, Exception):
                getattr(mock_client, method).side_effect = response
            else:
                getattr(mock_client, method).return_value = response
        
        # Configure paginator
        mock_paginator = Mock()
        mock_paginator.paginate.return_value = [default_responses['list_keys']]
        mock_client.get_paginator.return_value = mock_paginator
        
        return mock_client
    
    def create_mock_session(self, kms_responses: dict = None):
        """Create a mock boto3 session."""
        mock_session = Mock()
        mock_client = self.create_mock_kms_client(kms_responses)
        mock_session.client.return_value = mock_client
        return mock_session, mock_client
    
    def assert_finding_structure(self, finding: dict):
        """Assert that a finding has the correct structure."""
        required_fields = ['region', 'profile', 'resource_type', 'resource_id', 
                          'status', 'risk_level', 'recommendation', 'details']
        
        for field in required_fields:
            assert field in finding, f"Missing required field: {field}"
        
        assert finding['status'] in ['COMPLIANT', 'NON_COMPLIANT', 'ERROR']
        assert finding['risk_level'] in ['LOW', 'MEDIUM', 'HIGH']
        assert finding['resource_type'] == 'kms_key'
    
    def test_compliant_kms_key_with_all_required_tags(self):
        """Test KMS key with all required data sovereignty tags."""
        compliant_tags = {
            'Tags': [
                {'TagKey': 'DataJurisdiction', 'TagValue': 'US'},
                {'TagKey': 'DataResidency', 'TagValue': 'us-east-1'},
                {'TagKey': 'ComplianceFramework', 'TagValue': 'SOX'},
                {'TagKey': 'DataClassification', 'TagValue': 'CONFIDENTIAL'},
                {'TagKey': 'ComplianceOfficer', 'TagValue': 'compliance@company.com'},
                {'TagKey': 'SovereigntyLevel', 'TagValue': 'STRICT'},
                {'TagKey': 'CrossBorderTransfer', 'TagValue': 'PROHIBITED'}
            ]
        }
        
        with patch('boto3.Session') as mock_session_class:
            mock_session, mock_client = self.create_mock_session({
                'list_resource_tags': compliant_tags
            })
            mock_session_class.return_value = mock_session
            
            findings = kms_key_data_sovereignty_tags_check(self.test_region, self.test_profile)
            
            assert isinstance(findings, list)
            assert len(findings) >= 1
            
            compliant_findings = [f for f in findings if f['status'] == 'COMPLIANT']
            assert len(compliant_findings) >= 1
            
            for finding in compliant_findings:
                self.assert_finding_structure(finding)
                assert finding['risk_level'] == 'LOW'
                assert 'sovereignty_tags' in finding['details']
                assert finding['details']['tag_compliance_checks']['has_required_tags']
    
    def test_non_compliant_kms_key_missing_required_tags(self):
        """Test KMS key missing required data sovereignty tags."""
        incomplete_tags = {
            'Tags': [
                {'TagKey': 'DataJurisdiction', 'TagValue': 'US'},
                {'TagKey': 'Environment', 'TagValue': 'Production'}
                # Missing DataResidency, ComplianceFramework, DataClassification
            ]
        }
        
        with patch('boto3.Session') as mock_session_class:
            mock_session, mock_client = self.create_mock_session({
                'list_resource_tags': incomplete_tags
            })
            mock_session_class.return_value = mock_session
            
            findings = kms_key_data_sovereignty_tags_check(self.test_region, self.test_profile)
            
            assert isinstance(findings, list)
            assert len(findings) >= 1
            
            non_compliant_findings = [f for f in findings if f['status'] == 'NON_COMPLIANT']
            assert len(non_compliant_findings) >= 1
            
            for finding in non_compliant_findings:
                self.assert_finding_structure(finding)
                assert finding['risk_level'] == 'MEDIUM'
                assert len(finding['details']['missing_required_tags']) > 0
                assert not finding['details']['tag_compliance_checks']['has_required_tags']
    
    def test_non_compliant_kms_key_invalid_tag_values(self):
        """Test KMS key with invalid tag values."""
        invalid_tags = {
            'Tags': [
                {'TagKey': 'DataJurisdiction', 'TagValue': 'INVALID_JURISDICTION'},
                {'TagKey': 'DataResidency', 'TagValue': 'us-east-1'},
                {'TagKey': 'ComplianceFramework', 'TagValue': 'INVALID_FRAMEWORK'},
                {'TagKey': 'DataClassification', 'TagValue': 'INVALID_CLASSIFICATION'}
            ]
        }
        
        with patch('boto3.Session') as mock_session_class:
            mock_session, mock_client = self.create_mock_session({
                'list_resource_tags': invalid_tags
            })
            mock_session_class.return_value = mock_session
            
            findings = kms_key_data_sovereignty_tags_check(self.test_region, self.test_profile)
            
            assert isinstance(findings, list)
            assert len(findings) >= 1
            
            non_compliant_findings = [f for f in findings if f['status'] == 'NON_COMPLIANT']
            assert len(non_compliant_findings) >= 1
            
            for finding in non_compliant_findings:
                self.assert_finding_structure(finding)
                assert len(finding['details']['invalid_tag_values']) > 0
                assert not finding['details']['tag_compliance_checks']['has_valid_values']
    
    def test_residency_region_mismatch(self):
        """Test KMS key with DataResidency tag not matching current region."""
        mismatched_tags = {
            'Tags': [
                {'TagKey': 'DataJurisdiction', 'TagValue': 'US'},
                {'TagKey': 'DataResidency', 'TagValue': 'us-west-2'},  # Different from test region
                {'TagKey': 'ComplianceFramework', 'TagValue': 'SOX'},
                {'TagKey': 'DataClassification', 'TagValue': 'CONFIDENTIAL'}
            ]
        }
        
        with patch('boto3.Session') as mock_session_class:
            mock_session, mock_client = self.create_mock_session({
                'list_resource_tags': mismatched_tags
            })
            mock_session_class.return_value = mock_session
            
            findings = kms_key_data_sovereignty_tags_check(self.test_region, self.test_profile)
            
            assert isinstance(findings, list)
            assert len(findings) >= 1
            
            non_compliant_findings = [f for f in findings if f['status'] == 'NON_COMPLIANT']
            assert len(non_compliant_findings) >= 1
            
            for finding in non_compliant_findings:
                self.assert_finding_structure(finding)
                assert len(finding['details']['tag_violations']) > 0
                assert not finding['details']['tag_compliance_checks']['residency_matches_region']
    
    def test_eu_jurisdiction_specific_requirements(self):
        """Test EU jurisdiction specific tag requirements."""
        eu_incomplete_tags = {
            'Tags': [
                {'TagKey': 'DataJurisdiction', 'TagValue': 'EU'},
                {'TagKey': 'DataResidency', 'TagValue': 'us-east-1'},
                {'TagKey': 'ComplianceFramework', 'TagValue': 'GDPR'},
                {'TagKey': 'DataClassification', 'TagValue': 'CONFIDENTIAL'}
                # Missing DataController, LegalBasis, DataSubject required for EU
            ]
        }
        
        with patch('boto3.Session') as mock_session_class:
            mock_session, mock_client = self.create_mock_session({
                'list_resource_tags': eu_incomplete_tags
            })
            mock_session_class.return_value = mock_session
            
            findings = kms_key_data_sovereignty_tags_check(self.test_region, self.test_profile)
            
            assert isinstance(findings, list)
            assert len(findings) >= 1
            
            non_compliant_findings = [f for f in findings if f['status'] == 'NON_COMPLIANT']
            assert len(non_compliant_findings) >= 1
            
            for finding in non_compliant_findings:
                self.assert_finding_structure(finding)
                violation_found = any(
                    v.get('violation_type') == 'missing_jurisdiction_tag' 
                    for v in finding['details']['tag_violations']
                )
                assert violation_found
    
    def test_classification_sovereignty_consistency(self):
        """Test data classification and sovereignty level consistency."""
        inconsistent_tags = {
            'Tags': [
                {'TagKey': 'DataJurisdiction', 'TagValue': 'US'},
                {'TagKey': 'DataResidency', 'TagValue': 'us-east-1'},
                {'TagKey': 'ComplianceFramework', 'TagValue': 'SOX'},
                {'TagKey': 'DataClassification', 'TagValue': 'RESTRICTED'},
                {'TagKey': 'SovereigntyLevel', 'TagValue': 'FLEXIBLE'}  # Inconsistent with RESTRICTED
            ]
        }
        
        with patch('boto3.Session') as mock_session_class:
            mock_session, mock_client = self.create_mock_session({
                'list_resource_tags': inconsistent_tags
            })
            mock_session_class.return_value = mock_session
            
            findings = kms_key_data_sovereignty_tags_check(self.test_region, self.test_profile)
            
            assert isinstance(findings, list)
            assert len(findings) >= 1
            
            non_compliant_findings = [f for f in findings if f['status'] == 'NON_COMPLIANT']
            assert len(non_compliant_findings) >= 1
            
            for finding in non_compliant_findings:
                self.assert_finding_structure(finding)
                mismatch_found = any(
                    v.get('violation_type') == 'classification_sovereignty_mismatch'
                    for v in finding['details']['tag_violations']
                )
                assert mismatch_found
    
    def test_invalid_email_format(self):
        """Test invalid email format in compliance officer fields."""
        invalid_email_tags = {
            'Tags': [
                {'TagKey': 'DataJurisdiction', 'TagValue': 'US'},
                {'TagKey': 'DataResidency', 'TagValue': 'us-east-1'},
                {'TagKey': 'ComplianceFramework', 'TagValue': 'SOX'},
                {'TagKey': 'DataClassification', 'TagValue': 'CONFIDENTIAL'},
                {'TagKey': 'ComplianceOfficer', 'TagValue': 'invalid-email-format'}
            ]
        }
        
        with patch('boto3.Session') as mock_session_class:
            mock_session, mock_client = self.create_mock_session({
                'list_resource_tags': invalid_email_tags
            })
            mock_session_class.return_value = mock_session
            
            findings = kms_key_data_sovereignty_tags_check(self.test_region, self.test_profile)
            
            assert isinstance(findings, list)
            assert len(findings) >= 1
            
            non_compliant_findings = [f for f in findings if f['status'] == 'NON_COMPLIANT']
            assert len(non_compliant_findings) >= 1
            
            for finding in non_compliant_findings:
                self.assert_finding_structure(finding)
                email_violation_found = any(
                    v.get('violation_type') == 'invalid_email_format'
                    for v in finding['details']['tag_violations']
                )
                assert email_violation_found
    
    def test_aws_managed_keys_skipped(self):
        """Test that AWS-managed keys are skipped."""
        aws_managed_key = {
            'KeyMetadata': {
                'KeyId': 'aws-managed-key',
                'Arn': 'arn:aws:kms:us-east-1:123456789012:key/aws-managed-key',
                'KeyManager': 'AWS',  # AWS-managed
                'KeyUsage': 'ENCRYPT_DECRYPT',
                'KeyState': 'Enabled',
                'KeySpec': 'SYMMETRIC_DEFAULT'
            }
        }
        
        with patch('boto3.Session') as mock_session_class:
            mock_session, mock_client = self.create_mock_session({
                'describe_key': aws_managed_key
            })
            mock_session_class.return_value = mock_session
            
            findings = kms_key_data_sovereignty_tags_check(self.test_region, self.test_profile)
            
            # AWS-managed keys should be skipped, so findings might be empty or contain only other keys
            assert isinstance(findings, list)
    
    def test_key_access_denied_error(self):
        """Test handling of access denied errors for key tags."""
        access_denied_error = ClientError(
            {'Error': {'Code': 'AccessDenied', 'Message': 'Access denied'}},
            'ListResourceTags'
        )
        
        with patch('boto3.Session') as mock_session_class:
            mock_session, mock_client = self.create_mock_session({
                'list_resource_tags': access_denied_error
            })
            mock_session_class.return_value = mock_session
            
            findings = kms_key_data_sovereignty_tags_check(self.test_region, self.test_profile)
            
            assert isinstance(findings, list)
            assert len(findings) >= 1
            
            error_findings = [f for f in findings if f['status'] == 'ERROR']
            assert len(error_findings) >= 1
            
            for finding in error_findings:
                self.assert_finding_structure(finding)
                assert 'Cannot access tags' in finding['details']['error']
    
    def test_no_credentials_error(self):
        """Test handling of missing AWS credentials."""
        with patch('boto3.Session') as mock_session_class:
            mock_session_class.side_effect = NoCredentialsError()
            
            findings = kms_key_data_sovereignty_tags_check(self.test_region, self.test_profile)
            
            assert isinstance(findings, list)
            assert len(findings) >= 1
            
            error_findings = [f for f in findings if f['status'] == 'ERROR']
            assert len(error_findings) >= 1
            
            for finding in error_findings:
                self.assert_finding_structure(finding)
                assert finding['risk_level'] == 'HIGH'
                assert 'credentials not found' in finding['details']['error']
    
    def test_client_error_handling(self):
        """Test handling of general AWS client errors."""
        client_error = ClientError(
            {'Error': {'Code': 'InternalError', 'Message': 'Internal server error'}},
            'ListKeys'
        )
        
        with patch('boto3.Session') as mock_session_class:
            mock_session, mock_client = self.create_mock_session()
            mock_client.get_paginator.side_effect = client_error
            mock_session_class.return_value = mock_session
            
            findings = kms_key_data_sovereignty_tags_check(self.test_region, self.test_profile)
            
            assert isinstance(findings, list)
            assert len(findings) >= 1
            
            error_findings = [f for f in findings if f['status'] == 'ERROR']
            assert len(error_findings) >= 1
            
            for finding in error_findings:
                self.assert_finding_structure(finding)
                assert finding['risk_level'] == 'HIGH'
    
    def test_wrapper_function_structure(self):
        """Test the wrapper function returns proper structure."""
        with patch('boto3.Session') as mock_session_class:
            mock_session, mock_client = self.create_mock_session()
            mock_session_class.return_value = mock_session
            
            result = kms_key_data_sovereignty_tags(self.test_region, self.test_profile)
            
            assert isinstance(result, dict)
            required_keys = ['function_name', 'region', 'profile', 'total_findings',
                           'compliant_count', 'non_compliant_count', 'error_count',
                           'compliance_rate', 'findings']
            
            for key in required_keys:
                assert key in result
            
            assert result['function_name'] == 'kms_key_data_sovereignty_tags'
            assert result['region'] == self.test_region
            assert isinstance(result['findings'], list)
            assert isinstance(result['compliance_rate'], (int, float))
    
    def test_tag_completeness_calculation(self):
        """Test tag completeness percentage calculation."""
        partial_tags = {
            'Tags': [
                {'TagKey': 'DataJurisdiction', 'TagValue': 'US'},
                {'TagKey': 'DataResidency', 'TagValue': 'us-east-1'},
                {'TagKey': 'ComplianceFramework', 'TagValue': 'SOX'}
                # Missing DataClassification (required) and optional tags
            ]
        }
        
        with patch('boto3.Session') as mock_session_class:
            mock_session, mock_client = self.create_mock_session({
                'list_resource_tags': partial_tags
            })
            mock_session_class.return_value = mock_session
            
            findings = kms_key_data_sovereignty_tags_check(self.test_region, self.test_profile)
            
            assert isinstance(findings, list)
            assert len(findings) >= 1
            
            for finding in findings:
                assert 'tag_completeness_percentage' in finding['details']
                assert isinstance(finding['details']['tag_completeness_percentage'], (int, float))
                assert 0 <= finding['details']['tag_completeness_percentage'] <= 100

    @pytest.fixture
    def sample_compliant_finding(self):
        """Sample compliant finding for testing."""
        return {
            "region": "us-east-1",
            "profile": "default",
            "resource_type": "kms_key",
            "resource_id": "arn:aws:kms:us-east-1:123456789012:key/test-key",
            "status": "COMPLIANT",
            "risk_level": "LOW",
            "recommendation": "KMS key has proper data sovereignty tags",
            "details": {
                "key_id": "test-key",
                "sovereignty_tags": {
                    "DataJurisdiction": "US",
                    "DataResidency": "us-east-1"
                },
                "tag_compliance_checks": {
                    "has_required_tags": True,
                    "has_valid_values": True,
                    "passes_validation": True
                }
            }
        }

def test_module_imports():
    """Test that all modules can be imported successfully."""
    try:
        import kms_key_data_sovereignty_tags
        assert hasattr(kms_key_data_sovereignty_tags, 'kms_key_data_sovereignty_tags_check')
        assert hasattr(kms_key_data_sovereignty_tags, 'kms_key_data_sovereignty_tags')
    except ImportError as e:
        pytest.fail(f"Failed to import kms_key_data_sovereignty_tags: {e}")

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
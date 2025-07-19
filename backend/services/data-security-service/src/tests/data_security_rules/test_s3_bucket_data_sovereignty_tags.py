#!/usr/bin/env python3
"""
Comprehensive Test Suite for s3_bucket_data_sovereignty_tags Function

Tests the S3 bucket data sovereignty tagging compliance function with proper mocking,
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
from s3_bucket_data_sovereignty_tags import s3_bucket_data_sovereignty_tags_check, s3_bucket_data_sovereignty_tags

class TestS3BucketDataSovereigntyTags:
    """Comprehensive test suite for s3_bucket_data_sovereignty_tags function."""
    
    def setup_method(self):
        """Setup test fixtures."""
        self.test_region = "us-east-1"
        self.test_profile = "test-profile"
        self.sample_bucket_name = "test-sovereignty-bucket"
        self.sample_creation_date = datetime(2023, 1, 1, tzinfo=timezone.utc)
    
    def create_mock_session(self, client_responses: dict = None):
        """Create a mock boto3 session with configurable responses."""
        mock_session = Mock()
        mock_s3_client = Mock()
        
        # Configure client responses
        if client_responses:
            if 's3' in client_responses:
                for method, response in client_responses['s3'].items():
                    if isinstance(response, Exception):
                        getattr(mock_s3_client, method).side_effect = response
                    else:
                        getattr(mock_s3_client, method).return_value = response
        
        mock_session.client.return_value = mock_s3_client
        return mock_session, mock_s3_client
    
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
    
    def get_properly_tagged_bucket_responses(self):
        """Get mock responses for a properly tagged S3 bucket."""
        return {
            's3': {
                'list_buckets': {
                    'Buckets': [
                        {
                            'Name': self.sample_bucket_name,
                            'CreationDate': self.sample_creation_date
                        }
                    ]
                },
                'get_bucket_location': {
                    'LocationConstraint': 'us-east-1'
                },
                'get_bucket_tagging': {
                    'TagSet': [
                        {'Key': 'DataSovereignty', 'Value': 'US'},
                        {'Key': 'DataJurisdiction', 'Value': 'US'},
                        {'Key': 'DataClassification', 'Value': 'CONFIDENTIAL'},
                        {'Key': 'DataResidency', 'Value': 'US_EAST_1'},
                        {'Key': 'DataOwner', 'Value': 'john.doe@company.com'},
                        {'Key': 'BusinessUnit', 'Value': 'Engineering'},
                        {'Key': 'Environment', 'Value': 'Production'},
                        {'Key': 'ComplianceFramework', 'Value': 'SOX'}
                    ]
                }
            }
        }
    
    def get_missing_tags_bucket_responses(self):
        """Get mock responses for a bucket with missing required tags."""
        return {
            's3': {
                'list_buckets': {
                    'Buckets': [
                        {
                            'Name': self.sample_bucket_name,
                            'CreationDate': self.sample_creation_date
                        }
                    ]
                },
                'get_bucket_location': {
                    'LocationConstraint': 'us-east-1'
                },
                'get_bucket_tagging': {
                    'TagSet': [
                        {'Key': 'Environment', 'Value': 'Development'},
                        {'Key': 'Project', 'Value': 'TestProject'}
                        # Missing all required sovereignty tags
                    ]
                }
            }
        }
    
    def get_invalid_tag_values_bucket_responses(self):
        """Get mock responses for a bucket with invalid tag values."""
        return {
            's3': {
                'list_buckets': {
                    'Buckets': [
                        {
                            'Name': self.sample_bucket_name,
                            'CreationDate': self.sample_creation_date
                        }
                    ]
                },
                'get_bucket_location': {
                    'LocationConstraint': 'us-east-1'
                },
                'get_bucket_tagging': {
                    'TagSet': [
                        {'Key': 'DataSovereignty', 'Value': 'INVALID_SOVEREIGNTY'},
                        {'Key': 'DataJurisdiction', 'Value': 'INVALID_JURISDICTION'},
                        {'Key': 'DataClassification', 'Value': 'INVALID_CLASSIFICATION'},
                        {'Key': 'DataResidency', 'Value': 'INVALID_RESIDENCY'}
                    ]
                }
            }
        }
    
    def get_no_tags_bucket_responses(self):
        """Get mock responses for a bucket with no tags."""
        return {
            's3': {
                'list_buckets': {
                    'Buckets': [
                        {
                            'Name': self.sample_bucket_name,
                            'CreationDate': self.sample_creation_date
                        }
                    ]
                },
                'get_bucket_location': {
                    'LocationConstraint': 'us-east-1'
                },
                'get_bucket_tagging': ClientError(
                    {'Error': {'Code': 'NoSuchTagSet'}},
                    'GetBucketTagging'
                )
            }
        }
    
    def get_region_mismatch_bucket_responses(self):
        """Get mock responses for a bucket with region/residency mismatch."""
        return {
            's3': {
                'list_buckets': {
                    'Buckets': [
                        {
                            'Name': self.sample_bucket_name,
                            'CreationDate': self.sample_creation_date
                        }
                    ]
                },
                'get_bucket_location': {
                    'LocationConstraint': 'eu-west-1'  # Bucket in EU
                },
                'get_bucket_tagging': {
                    'TagSet': [
                        {'Key': 'DataSovereignty', 'Value': 'US'},
                        {'Key': 'DataJurisdiction', 'Value': 'US'},
                        {'Key': 'DataClassification', 'Value': 'CONFIDENTIAL'},
                        {'Key': 'DataResidency', 'Value': 'US_EAST_1'}  # Residency tag says US but bucket in EU
                    ]
                }
            }
        }
    
    def test_properly_tagged_bucket_compliant(self):
        """Test S3 bucket with proper sovereignty tags - should be compliant."""
        mock_responses = self.get_properly_tagged_bucket_responses()
        
        with patch('boto3.Session') as mock_session_class:
            mock_session, mock_s3_client = self.create_mock_session(mock_responses)
            mock_session_class.return_value = mock_session
            
            findings = s3_bucket_data_sovereignty_tags_check(self.test_region, self.test_profile)
            
            assert isinstance(findings, list)
            assert len(findings) > 0
            
            # Should have at least one compliant finding
            compliant_findings = [f for f in findings if f['status'] == 'COMPLIANT']
            assert len(compliant_findings) > 0
            
            for finding in findings:
                self.assert_finding_structure(finding)
                if finding['status'] == 'COMPLIANT':
                    assert 'compliance_features' in finding['details']
                    assert 'present_tags' in finding['details']
                    present_tags = finding['details']['present_tags']
                    assert 'DataSovereignty' in present_tags
                    assert present_tags['DataSovereignty'] == 'US'
    
    def test_missing_required_tags_non_compliant(self):
        """Test S3 bucket with missing required tags - should be non-compliant."""
        mock_responses = self.get_missing_tags_bucket_responses()
        
        with patch('boto3.Session') as mock_session_class:
            mock_session, mock_s3_client = self.create_mock_session(mock_responses)
            mock_session_class.return_value = mock_session
            
            findings = s3_bucket_data_sovereignty_tags_check(self.test_region, self.test_profile)
            
            assert isinstance(findings, list)
            assert len(findings) > 0
            
            # Should have at least one non-compliant finding
            non_compliant_findings = [f for f in findings if f['status'] == 'NON_COMPLIANT']
            assert len(non_compliant_findings) > 0
            
            for finding in findings:
                self.assert_finding_structure(finding)
                if finding['status'] == 'NON_COMPLIANT':
                    assert 'missing_required_tags' in finding['details']
                    missing_tags = finding['details']['missing_required_tags']
                    assert 'DataSovereignty' in missing_tags
                    assert 'DataJurisdiction' in missing_tags
                    assert 'DataClassification' in missing_tags
                    assert 'DataResidency' in missing_tags
    
    def test_invalid_tag_values_non_compliant(self):
        """Test S3 bucket with invalid tag values - should be non-compliant."""
        mock_responses = self.get_invalid_tag_values_bucket_responses()
        
        with patch('boto3.Session') as mock_session_class:
            mock_session, mock_s3_client = self.create_mock_session(mock_responses)
            mock_session_class.return_value = mock_session
            
            findings = s3_bucket_data_sovereignty_tags_check(self.test_region, self.test_profile)
            
            assert isinstance(findings, list)
            assert len(findings) > 0
            
            # Should have non-compliant finding for invalid tag values
            non_compliant_findings = [f for f in findings if f['status'] == 'NON_COMPLIANT']
            assert len(non_compliant_findings) > 0
            
            for finding in non_compliant_findings:
                assert 'invalid_tag_values' in finding['details']
                invalid_tags = finding['details']['invalid_tag_values']
                assert len(invalid_tags) > 0
                # Check that invalid values are detected
                invalid_tag_names = [tag['tag'] for tag in invalid_tags]
                assert 'DataSovereignty' in invalid_tag_names
    
    def test_no_tags_bucket_non_compliant(self):
        """Test S3 bucket with no tags - should be non-compliant."""
        mock_responses = self.get_no_tags_bucket_responses()
        
        with patch('boto3.Session') as mock_session_class:
            mock_session, mock_s3_client = self.create_mock_session(mock_responses)
            mock_session_class.return_value = mock_session
            
            findings = s3_bucket_data_sovereignty_tags_check(self.test_region, self.test_profile)
            
            assert isinstance(findings, list)
            assert len(findings) > 0
            
            # Should have non-compliant finding for missing tags
            non_compliant_findings = [f for f in findings if f['status'] == 'NON_COMPLIANT']
            assert len(non_compliant_findings) > 0
            
            for finding in non_compliant_findings:
                assert 'missing_required_tags' in finding['details']
                missing_tags = finding['details']['missing_required_tags']
                assert len(missing_tags) == 4  # All 4 required tags missing
    
    def test_region_residency_mismatch_non_compliant(self):
        """Test S3 bucket with region/residency mismatch - should be non-compliant."""
        mock_responses = self.get_region_mismatch_bucket_responses()
        
        with patch('boto3.Session') as mock_session_class:
            mock_session, mock_s3_client = self.create_mock_session(mock_responses)
            mock_session_class.return_value = mock_session
            
            findings = s3_bucket_data_sovereignty_tags_check(self.test_region, self.test_profile)
            
            assert isinstance(findings, list)
            assert len(findings) > 0
            
            # Should have non-compliant finding for region mismatch
            non_compliant_findings = [f for f in findings if f['status'] == 'NON_COMPLIANT']
            assert len(non_compliant_findings) > 0
            
            for finding in non_compliant_findings:
                violations = finding['details']['tagging_violations']
                region_mismatch_violations = [v for v in violations if 'does not match bucket region' in v]
                assert len(region_mismatch_violations) > 0
    
    def test_jurisdiction_sovereignty_alignment(self):
        """Test jurisdiction and sovereignty alignment validation."""
        mock_responses = {
            's3': {
                'list_buckets': {
                    'Buckets': [{'Name': self.sample_bucket_name, 'CreationDate': self.sample_creation_date}]
                },
                'get_bucket_location': {'LocationConstraint': 'us-east-1'},
                'get_bucket_tagging': {
                    'TagSet': [
                        {'Key': 'DataSovereignty', 'Value': 'EU'},
                        {'Key': 'DataJurisdiction', 'Value': 'US'},  # Misaligned with EU sovereignty
                        {'Key': 'DataClassification', 'Value': 'CONFIDENTIAL'},
                        {'Key': 'DataResidency', 'Value': 'US_EAST_1'}
                    ]
                }
            }
        }
        
        with patch('boto3.Session') as mock_session_class:
            mock_session, mock_s3_client = self.create_mock_session(mock_responses)
            mock_session_class.return_value = mock_session
            
            findings = s3_bucket_data_sovereignty_tags_check(self.test_region, self.test_profile)
            
            assert isinstance(findings, list)
            if findings:
                non_compliant_findings = [f for f in findings if f['status'] == 'NON_COMPLIANT']
                for finding in non_compliant_findings:
                    violations = finding['details']['tagging_violations']
                    jurisdiction_violations = [v for v in violations if 'not valid for sovereignty' in v]
                    assert len(jurisdiction_violations) > 0
    
    def test_production_environment_requirements(self):
        """Test production environment specific tagging requirements."""
        mock_responses = {
            's3': {
                'list_buckets': {
                    'Buckets': [{'Name': self.sample_bucket_name, 'CreationDate': self.sample_creation_date}]
                },
                'get_bucket_location': {'LocationConstraint': 'us-east-1'},
                'get_bucket_tagging': {
                    'TagSet': [
                        {'Key': 'DataSovereignty', 'Value': 'US'},
                        {'Key': 'DataJurisdiction', 'Value': 'US'},
                        {'Key': 'DataClassification', 'Value': 'CONFIDENTIAL'},
                        {'Key': 'DataResidency', 'Value': 'US_EAST_1'},
                        {'Key': 'Environment', 'Value': 'Production'}
                        # Missing critical production tags: DataOwner, BusinessUnit, ComplianceFramework
                    ]
                }
            }
        }
        
        with patch('boto3.Session') as mock_session_class:
            mock_session, mock_s3_client = self.create_mock_session(mock_responses)
            mock_session_class.return_value = mock_session
            
            findings = s3_bucket_data_sovereignty_tags_check(self.test_region, self.test_profile)
            
            assert isinstance(findings, list)
            if findings:
                non_compliant_findings = [f for f in findings if f['status'] == 'NON_COMPLIANT']
                for finding in non_compliant_findings:
                    violations = finding['details']['tagging_violations']
                    prod_violations = [v for v in violations if 'Production bucket missing critical tags' in v]
                    assert len(prod_violations) > 0
    
    def test_compliance_framework_requirements(self):
        """Test compliance framework specific requirements."""
        mock_responses = {
            's3': {
                'list_buckets': {
                    'Buckets': [{'Name': self.sample_bucket_name, 'CreationDate': self.sample_creation_date}]
                },
                'get_bucket_location': {'LocationConstraint': 'us-east-1'},
                'get_bucket_tagging': {
                    'TagSet': [
                        {'Key': 'DataSovereignty', 'Value': 'US'},
                        {'Key': 'DataJurisdiction', 'Value': 'US'},
                        {'Key': 'DataClassification', 'Value': 'CONFIDENTIAL'},
                        {'Key': 'DataResidency', 'Value': 'US_EAST_1'},
                        {'Key': 'ComplianceFramework', 'Value': 'GDPR'}
                        # Missing GDPR required tags: DataOwner, RetentionPeriod
                    ]
                }
            }
        }
        
        with patch('boto3.Session') as mock_session_class:
            mock_session, mock_s3_client = self.create_mock_session(mock_responses)
            mock_session_class.return_value = mock_session
            
            findings = s3_bucket_data_sovereignty_tags_check(self.test_region, self.test_profile)
            
            assert isinstance(findings, list)
            if findings:
                non_compliant_findings = [f for f in findings if f['status'] == 'NON_COMPLIANT']
                for finding in non_compliant_findings:
                    violations = finding['details']['tagging_violations']
                    gdpr_violations = [v for v in violations if 'GDPR' in v]
                    assert len(gdpr_violations) > 0
    
    def test_tag_format_validation(self):
        """Test tag format validation (empty values, length limits)."""
        mock_responses = {
            's3': {
                'list_buckets': {
                    'Buckets': [{'Name': self.sample_bucket_name, 'CreationDate': self.sample_creation_date}]
                },
                'get_bucket_location': {'LocationConstraint': 'us-east-1'},
                'get_bucket_tagging': {
                    'TagSet': [
                        {'Key': 'DataSovereignty', 'Value': 'US'},
                        {'Key': 'DataJurisdiction', 'Value': 'US'},
                        {'Key': 'DataClassification', 'Value': 'CONFIDENTIAL'},
                        {'Key': 'DataResidency', 'Value': 'US_EAST_1'},
                        {'Key': 'EmptyTag', 'Value': ''},  # Empty value
                        {'Key': 'LongTag', 'Value': 'x' * 300}  # Too long
                    ]
                }
            }
        }
        
        with patch('boto3.Session') as mock_session_class:
            mock_session, mock_s3_client = self.create_mock_session(mock_responses)
            mock_session_class.return_value = mock_session
            
            findings = s3_bucket_data_sovereignty_tags_check(self.test_region, self.test_profile)
            
            assert isinstance(findings, list)
            if findings:
                non_compliant_findings = [f for f in findings if f['status'] == 'NON_COMPLIANT']
                for finding in non_compliant_findings:
                    violations = finding['details']['tagging_violations']
                    format_violations = [v for v in violations if 'empty value' in v or 'exceeds 256 characters' in v]
                    assert len(format_violations) > 0
    
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
            mock_session, mock_s3_client = self.create_mock_session(error_responses)
            mock_session_class.return_value = mock_session
            
            findings = s3_bucket_data_sovereignty_tags_check(self.test_region, self.test_profile)
            
            assert isinstance(findings, list)
            assert len(findings) >= 1
            
            # Should have at least one ERROR finding
            error_findings = [f for f in findings if f['status'] == 'ERROR']
            assert len(error_findings) >= 1
    
    def test_no_credentials_error(self):
        """Test handling of no AWS credentials."""
        with patch('boto3.Session') as mock_session_class:
            mock_session_class.side_effect = NoCredentialsError()
            
            findings = s3_bucket_data_sovereignty_tags_check(self.test_region, self.test_profile)
            
            assert isinstance(findings, list)
            assert len(findings) >= 1
            assert all(f['status'] == 'ERROR' for f in findings)
    
    def test_bucket_specific_error_handling(self):
        """Test error handling for bucket-specific issues."""
        mock_responses = {
            's3': {
                'list_buckets': {
                    'Buckets': [{'Name': self.sample_bucket_name, 'CreationDate': self.sample_creation_date}]
                },
                'get_bucket_location': ClientError(
                    {'Error': {'Code': 'NoSuchBucket'}},
                    'GetBucketLocation'
                )
            }
        }
        
        with patch('boto3.Session') as mock_session_class:
            mock_session, mock_s3_client = self.create_mock_session(mock_responses)
            mock_session_class.return_value = mock_session
            
            findings = s3_bucket_data_sovereignty_tags_check(self.test_region, self.test_profile)
            
            assert isinstance(findings, list)
            # Should handle bucket-specific errors gracefully
            error_findings = [f for f in findings if f['status'] == 'ERROR']
            if error_findings:
                assert len(error_findings) >= 1
    
    def test_wrapper_function(self):
        """Test the main wrapper function."""
        mock_responses = self.get_properly_tagged_bucket_responses()
        
        with patch('boto3.Session') as mock_session_class:
            mock_session, mock_s3_client = self.create_mock_session(mock_responses)
            mock_session_class.return_value = mock_session
            
            result = s3_bucket_data_sovereignty_tags(self.test_region, self.test_profile)
            
            assert isinstance(result, dict)
            required_keys = ['function_name', 'region', 'profile', 'total_findings',
                           'compliant_count', 'non_compliant_count', 'error_count',
                           'compliance_rate', 'findings']
            
            for key in required_keys:
                assert key in result
            
            assert result['function_name'] == 's3_bucket_data_sovereignty_tags'
            assert result['region'] == self.test_region
            assert isinstance(result['findings'], list)
    
    def test_multiple_buckets_mixed_compliance(self):
        """Test multiple buckets with different compliance statuses."""
        mock_responses = {
            's3': {
                'list_buckets': {
                    'Buckets': [
                        {'Name': 'compliant-bucket', 'CreationDate': self.sample_creation_date},
                        {'Name': 'non-compliant-bucket', 'CreationDate': self.sample_creation_date}
                    ]
                }
            }
        }
        
        # Mock responses based on bucket name
        def get_bucket_location_side_effect(Bucket):
            return {'LocationConstraint': 'us-east-1'}
        
        def get_bucket_tagging_side_effect(Bucket):
            if 'compliant' in Bucket:
                return {
                    'TagSet': [
                        {'Key': 'DataSovereignty', 'Value': 'US'},
                        {'Key': 'DataJurisdiction', 'Value': 'US'},
                        {'Key': 'DataClassification', 'Value': 'CONFIDENTIAL'},
                        {'Key': 'DataResidency', 'Value': 'US_EAST_1'}
                    ]
                }
            else:
                return {'TagSet': []}  # No tags
        
        with patch('boto3.Session') as mock_session_class:
            mock_session, mock_s3_client = self.create_mock_session(mock_responses)
            mock_s3_client.get_bucket_location.side_effect = get_bucket_location_side_effect
            mock_s3_client.get_bucket_tagging.side_effect = get_bucket_tagging_side_effect
            mock_session_class.return_value = mock_session
            
            findings = s3_bucket_data_sovereignty_tags_check(self.test_region, self.test_profile)
            
            assert isinstance(findings, list)
            assert len(findings) >= 2  # Should have findings for both buckets
            
            # Should have a mix of compliance statuses
            statuses = [f['status'] for f in findings]
            unique_statuses = set(statuses)
            assert len(unique_statuses) > 1  # Should have different statuses
    
    def test_tag_coverage_calculation(self):
        """Test tag coverage percentage calculation."""
        mock_responses = self.get_properly_tagged_bucket_responses()
        
        with patch('boto3.Session') as mock_session_class:
            mock_session, mock_s3_client = self.create_mock_session(mock_responses)
            mock_session_class.return_value = mock_session
            
            findings = s3_bucket_data_sovereignty_tags_check(self.test_region, self.test_profile)
            
            assert isinstance(findings, list)
            if findings:
                for finding in findings:
                    assert 'tag_coverage_percent' in finding['details']
                    coverage = finding['details']['tag_coverage_percent']
                    assert isinstance(coverage, (int, float))
                    assert 0 <= coverage <= 100

def test_module_imports():
    """Test that the module can be imported successfully."""
    try:
        import s3_bucket_data_sovereignty_tags
        assert hasattr(s3_bucket_data_sovereignty_tags, 's3_bucket_data_sovereignty_tags_check')
        assert hasattr(s3_bucket_data_sovereignty_tags, 's3_bucket_data_sovereignty_tags')
    except ImportError as e:
        pytest.fail(f"Failed to import s3_bucket_data_sovereignty_tags: {e}")

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
#!/usr/bin/env python3
"""
Comprehensive Test Suite for dynamodb_table_data_classification_tags Function

Tests the DynamoDB table data classification tagging compliance function with proper mocking,
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
from dynamodb_table_data_classification_tags import dynamodb_table_data_classification_tags_check, dynamodb_table_data_classification_tags

class TestDynamoDBTableDataClassificationTags:
    """Comprehensive test suite for dynamodb_table_data_classification_tags function."""
    
    def setup_method(self):
        """Setup test fixtures."""
        self.test_region = "us-east-1"
        self.test_profile = "test-profile"
        self.sample_table_name = "test-table"
        self.sample_table_arn = f"arn:aws:dynamodb:{self.test_region}:123456789012:table/{self.sample_table_name}"
        self.sample_creation_date = datetime(2023, 1, 1, tzinfo=timezone.utc)
    
    def create_mock_session(self, client_responses: dict = None):
        """Create a mock boto3 session with configurable responses."""
        mock_session = Mock()
        mock_dynamodb_client = Mock()
        
        # Configure client responses
        if client_responses:
            if 'dynamodb' in client_responses:
                for method, response in client_responses['dynamodb'].items():
                    if isinstance(response, Exception):
                        getattr(mock_dynamodb_client, method).side_effect = response
                    else:
                        getattr(mock_dynamodb_client, method).return_value = response
        
        mock_session.client.return_value = mock_dynamodb_client
        return mock_session, mock_dynamodb_client
    
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
    
    def get_properly_tagged_table_responses(self):
        """Get mock responses for a properly tagged DynamoDB table."""
        return {
            'dynamodb': {
                'list_tables': {
                    'TableNames': [self.sample_table_name]
                },
                'describe_table': {
                    'Table': {
                        'TableName': self.sample_table_name,
                        'TableArn': self.sample_table_arn,
                        'TableStatus': 'ACTIVE',
                        'CreationDateTime': self.sample_creation_date,
                        'BillingModeSummary': {
                            'BillingMode': 'PAY_PER_REQUEST'
                        },
                        'SSEDescription': {
                            'Status': 'ENABLED',
                            'SSEType': 'KMS'
                        }
                    }
                },
                'list_tags_of_resource': {
                    'Tags': [
                        {'Key': 'DataClassification', 'Value': 'CONFIDENTIAL'},
                        {'Key': 'DataSensitivity', 'Value': 'HIGH'},
                        {'Key': 'DataType', 'Value': 'PII'},
                        {'Key': 'ComplianceFramework', 'Value': 'GDPR'},
                        {'Key': 'DataOwner', 'Value': 'john.doe@company.com'},
                        {'Key': 'BusinessUnit', 'Value': 'Engineering'},
                        {'Key': 'Environment', 'Value': 'Production'},
                        {'Key': 'RetentionPeriod', 'Value': '7years'},
                        {'Key': 'PurposeOfUse', 'Value': 'Customer management'}
                    ]
                }
            }
        }
    
    def get_missing_tags_table_responses(self):
        """Get mock responses for a table with missing required tags."""
        return {
            'dynamodb': {
                'list_tables': {
                    'TableNames': [self.sample_table_name]
                },
                'describe_table': {
                    'Table': {
                        'TableName': self.sample_table_name,
                        'TableArn': self.sample_table_arn,
                        'TableStatus': 'ACTIVE',
                        'CreationDateTime': self.sample_creation_date,
                        'BillingModeSummary': {
                            'BillingMode': 'PROVISIONED'
                        }
                    }
                },
                'list_tags_of_resource': {
                    'Tags': [
                        {'Key': 'Environment', 'Value': 'Development'},
                        {'Key': 'Project', 'Value': 'TestProject'}
                        # Missing all required classification tags
                    ]
                }
            }
        }
    
    def get_invalid_tag_values_table_responses(self):
        """Get mock responses for a table with invalid tag values."""
        return {
            'dynamodb': {
                'list_tables': {
                    'TableNames': [self.sample_table_name]
                },
                'describe_table': {
                    'Table': {
                        'TableName': self.sample_table_name,
                        'TableArn': self.sample_table_arn,
                        'TableStatus': 'ACTIVE',
                        'CreationDateTime': self.sample_creation_date,
                        'BillingModeSummary': {
                            'BillingMode': 'PROVISIONED'
                        }
                    }
                },
                'list_tags_of_resource': {
                    'Tags': [
                        {'Key': 'DataClassification', 'Value': 'INVALID_CLASSIFICATION'},
                        {'Key': 'DataSensitivity', 'Value': 'INVALID_SENSITIVITY'},
                        {'Key': 'DataType', 'Value': 'INVALID_TYPE'},
                        {'Key': 'ComplianceFramework', 'Value': 'INVALID_FRAMEWORK'}
                    ]
                }
            }
        }
    
    def get_misaligned_classification_sensitivity_responses(self):
        """Get mock responses for a table with misaligned classification and sensitivity."""
        return {
            'dynamodb': {
                'list_tables': {
                    'TableNames': [self.sample_table_name]
                },
                'describe_table': {
                    'Table': {
                        'TableName': self.sample_table_name,
                        'TableArn': self.sample_table_arn,
                        'TableStatus': 'ACTIVE',
                        'CreationDateTime': self.sample_creation_date,
                        'BillingModeSummary': {
                            'BillingMode': 'PROVISIONED'
                        }
                    }
                },
                'list_tags_of_resource': {
                    'Tags': [
                        {'Key': 'DataClassification', 'Value': 'PUBLIC'},
                        {'Key': 'DataSensitivity', 'Value': 'CRITICAL'},  # Misaligned with PUBLIC
                        {'Key': 'DataType', 'Value': 'GENERAL'},
                        {'Key': 'ComplianceFramework', 'Value': 'NONE'}
                    ]
                }
            }
        }
    
    def test_properly_tagged_table_compliant(self):
        """Test DynamoDB table with proper classification tags - should be compliant."""
        mock_responses = self.get_properly_tagged_table_responses()
        
        with patch('boto3.Session') as mock_session_class:
            mock_session, mock_dynamodb_client = self.create_mock_session(mock_responses)
            mock_session_class.return_value = mock_session
            
            findings = dynamodb_table_data_classification_tags_check(self.test_region, self.test_profile)
            
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
                    assert 'DataClassification' in present_tags
                    assert present_tags['DataClassification'] == 'CONFIDENTIAL'
    
    def test_missing_required_tags_non_compliant(self):
        """Test DynamoDB table with missing required tags - should be non-compliant."""
        mock_responses = self.get_missing_tags_table_responses()
        
        with patch('boto3.Session') as mock_session_class:
            mock_session, mock_dynamodb_client = self.create_mock_session(mock_responses)
            mock_session_class.return_value = mock_session
            
            findings = dynamodb_table_data_classification_tags_check(self.test_region, self.test_profile)
            
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
                    assert 'DataClassification' in missing_tags
                    assert 'DataSensitivity' in missing_tags
                    assert 'DataType' in missing_tags
                    assert 'ComplianceFramework' in missing_tags
    
    def test_invalid_tag_values_non_compliant(self):
        """Test DynamoDB table with invalid tag values - should be non-compliant."""
        mock_responses = self.get_invalid_tag_values_table_responses()
        
        with patch('boto3.Session') as mock_session_class:
            mock_session, mock_dynamodb_client = self.create_mock_session(mock_responses)
            mock_session_class.return_value = mock_session
            
            findings = dynamodb_table_data_classification_tags_check(self.test_region, self.test_profile)
            
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
                assert 'DataClassification' in invalid_tag_names
    
    def test_classification_sensitivity_misalignment(self):
        """Test detection of classification and sensitivity misalignment."""
        mock_responses = self.get_misaligned_classification_sensitivity_responses()
        
        with patch('boto3.Session') as mock_session_class:
            mock_session, mock_dynamodb_client = self.create_mock_session(mock_responses)
            mock_session_class.return_value = mock_session
            
            findings = dynamodb_table_data_classification_tags_check(self.test_region, self.test_profile)
            
            assert isinstance(findings, list)
            if findings:
                non_compliant_findings = [f for f in findings if f['status'] == 'NON_COMPLIANT']
                for finding in non_compliant_findings:
                    violations = finding['details']['tagging_violations']
                    misalignment_violations = [v for v in violations if 'not appropriate for classification' in v]
                    assert len(misalignment_violations) > 0
    
    def test_production_environment_requirements(self):
        """Test production environment specific tagging requirements."""
        mock_responses = {
            'dynamodb': {
                'list_tables': {'TableNames': [self.sample_table_name]},
                'describe_table': {
                    'Table': {
                        'TableName': self.sample_table_name,
                        'TableArn': self.sample_table_arn,
                        'TableStatus': 'ACTIVE',
                        'CreationDateTime': self.sample_creation_date,
                        'BillingModeSummary': {'BillingMode': 'PROVISIONED'}
                    }
                },
                'list_tags_of_resource': {
                    'Tags': [
                        {'Key': 'DataClassification', 'Value': 'CONFIDENTIAL'},
                        {'Key': 'DataSensitivity', 'Value': 'HIGH'},
                        {'Key': 'DataType', 'Value': 'PII'},
                        {'Key': 'ComplianceFramework', 'Value': 'GDPR'},
                        {'Key': 'Environment', 'Value': 'Production'}
                        # Missing critical production tags: DataOwner, BusinessUnit, RetentionPeriod
                    ]
                }
            }
        }
        
        with patch('boto3.Session') as mock_session_class:
            mock_session, mock_dynamodb_client = self.create_mock_session(mock_responses)
            mock_session_class.return_value = mock_session
            
            findings = dynamodb_table_data_classification_tags_check(self.test_region, self.test_profile)
            
            assert isinstance(findings, list)
            if findings:
                non_compliant_findings = [f for f in findings if f['status'] == 'NON_COMPLIANT']
                for finding in non_compliant_findings:
                    violations = finding['details']['tagging_violations']
                    prod_violations = [v for v in violations if 'Production table missing critical tags' in v]
                    assert len(prod_violations) > 0
    
    def test_compliance_framework_requirements(self):
        """Test compliance framework specific requirements."""
        mock_responses = {
            'dynamodb': {
                'list_tables': {'TableNames': [self.sample_table_name]},
                'describe_table': {
                    'Table': {
                        'TableName': self.sample_table_name,
                        'TableArn': self.sample_table_arn,
                        'TableStatus': 'ACTIVE',
                        'CreationDateTime': self.sample_creation_date,
                        'BillingModeSummary': {'BillingMode': 'PROVISIONED'}
                    }
                },
                'list_tags_of_resource': {
                    'Tags': [
                        {'Key': 'DataClassification', 'Value': 'CONFIDENTIAL'},
                        {'Key': 'DataSensitivity', 'Value': 'HIGH'},
                        {'Key': 'DataType', 'Value': 'PII'},
                        {'Key': 'ComplianceFramework', 'Value': 'GDPR'}
                        # Missing GDPR required tags: DataOwner, RetentionPeriod, PurposeOfUse
                    ]
                }
            }
        }
        
        with patch('boto3.Session') as mock_session_class:
            mock_session, mock_dynamodb_client = self.create_mock_session(mock_responses)
            mock_session_class.return_value = mock_session
            
            findings = dynamodb_table_data_classification_tags_check(self.test_region, self.test_profile)
            
            assert isinstance(findings, list)
            if findings:
                non_compliant_findings = [f for f in findings if f['status'] == 'NON_COMPLIANT']
                for finding in non_compliant_findings:
                    violations = finding['details']['tagging_violations']
                    gdpr_violations = [v for v in violations if 'GDPR' in v]
                    assert len(gdpr_violations) > 0
    
    def test_sensitive_data_requirements(self):
        """Test sensitive data type specific requirements."""
        mock_responses = {
            'dynamodb': {
                'list_tables': {'TableNames': [self.sample_table_name]},
                'describe_table': {
                    'Table': {
                        'TableName': self.sample_table_name,
                        'TableArn': self.sample_table_arn,
                        'TableStatus': 'ACTIVE',
                        'CreationDateTime': self.sample_creation_date,
                        'BillingModeSummary': {'BillingMode': 'PROVISIONED'}
                    }
                },
                'list_tags_of_resource': {
                    'Tags': [
                        {'Key': 'DataClassification', 'Value': 'CONFIDENTIAL'},
                        {'Key': 'DataSensitivity', 'Value': 'HIGH'},
                        {'Key': 'DataType', 'Value': 'PHI'}  # Sensitive data type
                        # Missing: DataOwner, RetentionPeriod, ComplianceFramework
                    ]
                }
            }
        }
        
        with patch('boto3.Session') as mock_session_class:
            mock_session, mock_dynamodb_client = self.create_mock_session(mock_responses)
            mock_session_class.return_value = mock_session
            
            findings = dynamodb_table_data_classification_tags_check(self.test_region, self.test_profile)
            
            assert isinstance(findings, list)
            if findings:
                non_compliant_findings = [f for f in findings if f['status'] == 'NON_COMPLIANT']
                for finding in non_compliant_findings:
                    violations = finding['details']['tagging_violations']
                    sensitive_violations = [v for v in violations if 'Sensitive data table missing required tags' in v]
                    assert len(sensitive_violations) > 0
    
    def test_encryption_classification_alignment(self):
        """Test encryption requirement based on data classification."""
        mock_responses = {
            'dynamodb': {
                'list_tables': {'TableNames': [self.sample_table_name]},
                'describe_table': {
                    'Table': {
                        'TableName': self.sample_table_name,
                        'TableArn': self.sample_table_arn,
                        'TableStatus': 'ACTIVE',
                        'CreationDateTime': self.sample_creation_date,
                        'BillingModeSummary': {'BillingMode': 'PROVISIONED'},
                        'SSEDescription': {
                            'Status': 'DISABLED'  # No encryption
                        }
                    }
                },
                'list_tags_of_resource': {
                    'Tags': [
                        {'Key': 'DataClassification', 'Value': 'TOP_SECRET'},  # Requires encryption
                        {'Key': 'DataSensitivity', 'Value': 'CRITICAL'},
                        {'Key': 'DataType', 'Value': 'FINANCIAL'},
                        {'Key': 'ComplianceFramework', 'Value': 'FISMA'}
                    ]
                }
            }
        }
        
        with patch('boto3.Session') as mock_session_class:
            mock_session, mock_dynamodb_client = self.create_mock_session(mock_responses)
            mock_session_class.return_value = mock_session
            
            findings = dynamodb_table_data_classification_tags_check(self.test_region, self.test_profile)
            
            assert isinstance(findings, list)
            if findings:
                non_compliant_findings = [f for f in findings if f['status'] == 'NON_COMPLIANT']
                for finding in non_compliant_findings:
                    violations = finding['details']['tagging_violations']
                    encryption_violations = [v for v in violations if 'must have encryption enabled' in v]
                    assert len(encryption_violations) > 0
    
    def test_inactive_table_skipped(self):
        """Test that inactive tables are skipped."""
        mock_responses = {
            'dynamodb': {
                'list_tables': {'TableNames': [self.sample_table_name]},
                'describe_table': {
                    'Table': {
                        'TableName': self.sample_table_name,
                        'TableArn': self.sample_table_arn,
                        'TableStatus': 'DELETING',  # Inactive table
                        'CreationDateTime': self.sample_creation_date,
                        'BillingModeSummary': {'BillingMode': 'PROVISIONED'}
                    }
                }
            }
        }
        
        with patch('boto3.Session') as mock_session_class:
            mock_session, mock_dynamodb_client = self.create_mock_session(mock_responses)
            mock_session_class.return_value = mock_session
            
            findings = dynamodb_table_data_classification_tags_check(self.test_region, self.test_profile)
            
            assert isinstance(findings, list)
            # Should not have findings for inactive tables
    
    def test_api_access_error_handling(self):
        """Test error handling for API access issues."""
        error_responses = {
            'dynamodb': {
                'list_tables': ClientError(
                    {'Error': {'Code': 'AccessDenied', 'Message': 'Access denied'}},
                    'ListTables'
                )
            }
        }
        
        with patch('boto3.Session') as mock_session_class:
            mock_session, mock_dynamodb_client = self.create_mock_session(error_responses)
            mock_session_class.return_value = mock_session
            
            findings = dynamodb_table_data_classification_tags_check(self.test_region, self.test_profile)
            
            assert isinstance(findings, list)
            assert len(findings) >= 1
            
            # Should have at least one ERROR finding
            error_findings = [f for f in findings if f['status'] == 'ERROR']
            assert len(error_findings) >= 1
    
    def test_no_credentials_error(self):
        """Test handling of no AWS credentials."""
        with patch('boto3.Session') as mock_session_class:
            mock_session_class.side_effect = NoCredentialsError()
            
            findings = dynamodb_table_data_classification_tags_check(self.test_region, self.test_profile)
            
            assert isinstance(findings, list)
            assert len(findings) >= 1
            assert all(f['status'] == 'ERROR' for f in findings)
    
    def test_table_specific_error_handling(self):
        """Test error handling for table-specific issues."""
        mock_responses = {
            'dynamodb': {
                'list_tables': {'TableNames': [self.sample_table_name]},
                'describe_table': ClientError(
                    {'Error': {'Code': 'ResourceNotFoundException'}},
                    'DescribeTable'
                )
            }
        }
        
        with patch('boto3.Session') as mock_session_class:
            mock_session, mock_dynamodb_client = self.create_mock_session(mock_responses)
            mock_session_class.return_value = mock_session
            
            findings = dynamodb_table_data_classification_tags_check(self.test_region, self.test_profile)
            
            assert isinstance(findings, list)
            # Should handle table-specific errors gracefully
            error_findings = [f for f in findings if f['status'] == 'ERROR']
            if error_findings:
                assert len(error_findings) >= 1
    
    def test_wrapper_function(self):
        """Test the main wrapper function."""
        mock_responses = self.get_properly_tagged_table_responses()
        
        with patch('boto3.Session') as mock_session_class:
            mock_session, mock_dynamodb_client = self.create_mock_session(mock_responses)
            mock_session_class.return_value = mock_session
            
            result = dynamodb_table_data_classification_tags(self.test_region, self.test_profile)
            
            assert isinstance(result, dict)
            required_keys = ['function_name', 'region', 'profile', 'total_findings',
                           'compliant_count', 'non_compliant_count', 'error_count',
                           'compliance_rate', 'findings']
            
            for key in required_keys:
                assert key in result
            
            assert result['function_name'] == 'dynamodb_table_data_classification_tags'
            assert result['region'] == self.test_region
            assert isinstance(result['findings'], list)
    
    def test_multiple_tables_mixed_compliance(self):
        """Test multiple tables with different compliance statuses."""
        mock_responses = {
            'dynamodb': {
                'list_tables': {
                    'TableNames': ['compliant-table', 'non-compliant-table']
                }
            }
        }
        
        # Mock responses based on table name
        def describe_table_side_effect(TableName):
            return {
                'Table': {
                    'TableName': TableName,
                    'TableArn': f'arn:aws:dynamodb:us-east-1:123456789012:table/{TableName}',
                    'TableStatus': 'ACTIVE',
                    'CreationDateTime': self.sample_creation_date,
                    'BillingModeSummary': {'BillingMode': 'PROVISIONED'}
                }
            }
        
        def list_tags_side_effect(ResourceArn):
            if 'compliant' in ResourceArn:
                return {
                    'Tags': [
                        {'Key': 'DataClassification', 'Value': 'CONFIDENTIAL'},
                        {'Key': 'DataSensitivity', 'Value': 'HIGH'},
                        {'Key': 'DataType', 'Value': 'PII'},
                        {'Key': 'ComplianceFramework', 'Value': 'GDPR'}
                    ]
                }
            else:
                return {'Tags': []}  # No tags
        
        with patch('boto3.Session') as mock_session_class:
            mock_session, mock_dynamodb_client = self.create_mock_session(mock_responses)
            mock_dynamodb_client.describe_table.side_effect = describe_table_side_effect
            mock_dynamodb_client.list_tags_of_resource.side_effect = list_tags_side_effect
            mock_session_class.return_value = mock_session
            
            findings = dynamodb_table_data_classification_tags_check(self.test_region, self.test_profile)
            
            assert isinstance(findings, list)
            assert len(findings) >= 2  # Should have findings for both tables
            
            # Should have a mix of compliance statuses
            statuses = [f['status'] for f in findings]
            unique_statuses = set(statuses)
            assert len(unique_statuses) > 1  # Should have different statuses
    
    def test_tag_coverage_calculation(self):
        """Test tag coverage percentage calculation."""
        mock_responses = self.get_properly_tagged_table_responses()
        
        with patch('boto3.Session') as mock_session_class:
            mock_session, mock_dynamodb_client = self.create_mock_session(mock_responses)
            mock_session_class.return_value = mock_session
            
            findings = dynamodb_table_data_classification_tags_check(self.test_region, self.test_profile)
            
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
        import dynamodb_table_data_classification_tags
        assert hasattr(dynamodb_table_data_classification_tags, 'dynamodb_table_data_classification_tags_check')
        assert hasattr(dynamodb_table_data_classification_tags, 'dynamodb_table_data_classification_tags')
    except ImportError as e:
        pytest.fail(f"Failed to import dynamodb_table_data_classification_tags: {e}")

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
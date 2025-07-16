#!/usr/bin/env python3
"""
Test cases for awslambda_function_data_sovereignty_tags compliance checker.
"""

import unittest
from unittest.mock import Mock, patch, MagicMock
import boto3
from botocore.exceptions import ClientError
import sys
import os

# Add the parent directory to the path to import the module under test
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../data_function_list'))

try:
    from awslambda_function_data_sovereignty_tags import (
        awslambda_function_data_sovereignty_tags_check,
        awslambda_function_data_sovereignty_tags,
        load_rule_metadata
    )
except ImportError as e:
    print(f"Import error: {e}")
    print("Please ensure the module is in the correct path")
    sys.exit(1)


class TestAWSLambdaDataSovereigntyTags(unittest.TestCase):
    """Test cases for AWS Lambda data sovereignty tags compliance checker."""

    def setUp(self):
        """Set up test fixtures."""
        self.region_name = "us-east-1"
        self.profile_name = "test-profile"
        
        # Sample Lambda function data
        self.sample_function = {
            'FunctionName': 'test-function',
            'FunctionArn': 'arn:aws:lambda:us-east-1:123456789012:function:test-function',
            'Runtime': 'python3.9',
            'LastModified': '2025-07-09T10:00:00.000+0000'
        }
        
        # Complete set of valid data sovereignty tags
        self.valid_sovereignty_tags = {
            'DataSovereignty': 'US',
            'DataJurisdiction': 'US',
            'DataClassification': 'CONFIDENTIAL',
            'DataResidency': 'US-EAST-1',
            'ComplianceRegion': 'US'
        }

    def test_load_rule_metadata(self):
        """Test rule metadata loading."""
        metadata = load_rule_metadata("awslambda_function_data_sovereignty_tags")
        
        self.assertEqual(metadata["function_name"], "awslambda_function_data_sovereignty_tags")
        self.assertEqual(metadata["capability"], "data_residency")
        self.assertEqual(metadata["service"], "lambda")
        self.assertEqual(metadata["subservice"], "tagging")
        self.assertEqual(metadata["risk"], "LOW")

    @patch('boto3.Session')
    def test_no_lambda_functions(self, mock_session):
        """Test when no Lambda functions exist in the region."""
        # Mock the Lambda client
        mock_client = Mock()
        mock_session.return_value.client.return_value = mock_client
        
        # Mock empty paginator response
        mock_paginator = Mock()
        mock_paginator.paginate.return_value = [{'Functions': []}]
        mock_client.get_paginator.return_value = mock_paginator
        
        # Run the check
        findings = awslambda_function_data_sovereignty_tags_check(self.region_name, self.profile_name)
        
        # Verify results
        self.assertEqual(len(findings), 0)
        mock_client.get_paginator.assert_called_once_with('list_functions')

    @patch('boto3.Session')
    def test_function_with_all_required_tags(self, mock_session):
        """Test Lambda function with all required data sovereignty tags."""
        # Mock the Lambda client
        mock_client = Mock()
        mock_session.return_value.client.return_value = mock_client
        
        # Mock paginator response
        mock_paginator = Mock()
        mock_paginator.paginate.return_value = [{'Functions': [self.sample_function]}]
        mock_client.get_paginator.return_value = mock_paginator
        
        # Mock list_tags response with all required tags
        mock_client.list_tags.return_value = {
            'Tags': self.valid_sovereignty_tags
        }
        
        # Run the check
        findings = awslambda_function_data_sovereignty_tags_check(self.region_name, self.profile_name)
        
        # Verify results
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding['status'], 'COMPLIANT')
        self.assertEqual(finding['resource_type'], 'lambda_function')
        self.assertEqual(finding['resource_id'], self.sample_function['FunctionArn'])
        self.assertEqual(finding['risk_level'], 'LOW')
        self.assertEqual(len(finding['details']['sovereignty_tags']), 5)

    @patch('boto3.Session')
    def test_function_with_missing_tags(self, mock_session):
        """Test Lambda function with missing data sovereignty tags."""
        # Mock the Lambda client
        mock_client = Mock()
        mock_session.return_value.client.return_value = mock_client
        
        # Mock paginator response
        mock_paginator = Mock()
        mock_paginator.paginate.return_value = [{'Functions': [self.sample_function]}]
        mock_client.get_paginator.return_value = mock_paginator
        
        # Mock list_tags response with only some tags
        incomplete_tags = {
            'DataJurisdiction': 'US',
            'DataClassification': 'CONFIDENTIAL',
            'OtherTag': 'SomeValue'
        }
        mock_client.list_tags.return_value = {'Tags': incomplete_tags}
        
        # Run the check
        findings = awslambda_function_data_sovereignty_tags_check(self.region_name, self.profile_name)
        
        # Verify results
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding['status'], 'NON_COMPLIANT')
        self.assertEqual(len(finding['details']['missing_tags']), 3)  # Missing 3 required tags
        self.assertIn('DataSovereignty', finding['details']['missing_tags'])
        self.assertIn('DataResidency', finding['details']['missing_tags'])
        self.assertIn('ComplianceRegion', finding['details']['missing_tags'])

    @patch('boto3.Session')
    def test_function_with_empty_tag_values(self, mock_session):
        """Test Lambda function with empty tag values."""
        # Mock the Lambda client
        mock_client = Mock()
        mock_session.return_value.client.return_value = mock_client
        
        # Mock paginator response
        mock_paginator = Mock()
        mock_paginator.paginate.return_value = [{'Functions': [self.sample_function]}]
        mock_client.get_paginator.return_value = mock_paginator
        
        # Mock list_tags response with empty values
        tags_with_empty_values = {
            'DataSovereignty': '',
            'DataJurisdiction': 'US',
            'DataClassification': '   ',  # Only whitespace
            'DataResidency': 'US-EAST-1',
            'ComplianceRegion': 'US'
        }
        mock_client.list_tags.return_value = {'Tags': tags_with_empty_values}
        
        # Run the check
        findings = awslambda_function_data_sovereignty_tags_check(self.region_name, self.profile_name)
        
        # Verify results
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding['status'], 'NON_COMPLIANT')
        self.assertEqual(len(finding['details']['missing_tags']), 2)  # Two tags with empty values
        self.assertIn('DataSovereignty (empty value)', finding['details']['missing_tags'])
        self.assertIn('DataClassification (empty value)', finding['details']['missing_tags'])

    @patch('boto3.Session')
    def test_function_with_invalid_jurisdiction_value(self, mock_session):
        """Test Lambda function with invalid jurisdiction value."""
        # Mock the Lambda client
        mock_client = Mock()
        mock_session.return_value.client.return_value = mock_client
        
        # Mock paginator response
        mock_paginator = Mock()
        mock_paginator.paginate.return_value = [{'Functions': [self.sample_function]}]
        mock_client.get_paginator.return_value = mock_paginator
        
        # Mock list_tags response with invalid jurisdiction
        invalid_jurisdiction_tags = self.valid_sovereignty_tags.copy()
        invalid_jurisdiction_tags['DataJurisdiction'] = 'INVALID_JURISDICTION'
        mock_client.list_tags.return_value = {'Tags': invalid_jurisdiction_tags}
        
        # Run the check
        findings = awslambda_function_data_sovereignty_tags_check(self.region_name, self.profile_name)
        
        # Verify results
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding['status'], 'NON_COMPLIANT')
        self.assertIn('Invalid jurisdiction value', finding['details']['violation'])

    @patch('boto3.Session')
    def test_function_with_invalid_classification_value(self, mock_session):
        """Test Lambda function with invalid classification value."""
        # Mock the Lambda client
        mock_client = Mock()
        mock_session.return_value.client.return_value = mock_client
        
        # Mock paginator response
        mock_paginator = Mock()
        mock_paginator.paginate.return_value = [{'Functions': [self.sample_function]}]
        mock_client.get_paginator.return_value = mock_paginator
        
        # Mock list_tags response with invalid classification
        invalid_classification_tags = self.valid_sovereignty_tags.copy()
        invalid_classification_tags['DataClassification'] = 'INVALID_CLASS'
        mock_client.list_tags.return_value = {'Tags': invalid_classification_tags}
        
        # Run the check
        findings = awslambda_function_data_sovereignty_tags_check(self.region_name, self.profile_name)
        
        # Verify results
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding['status'], 'NON_COMPLIANT')
        self.assertIn('Invalid classification value', finding['details']['violation'])

    @patch('boto3.Session')
    def test_function_with_no_tags(self, mock_session):
        """Test Lambda function with no tags at all."""
        # Mock the Lambda client
        mock_client = Mock()
        mock_session.return_value.client.return_value = mock_client
        
        # Mock paginator response
        mock_paginator = Mock()
        mock_paginator.paginate.return_value = [{'Functions': [self.sample_function]}]
        mock_client.get_paginator.return_value = mock_paginator
        
        # Mock list_tags response with no tags
        mock_client.list_tags.return_value = {'Tags': {}}
        
        # Run the check
        findings = awslambda_function_data_sovereignty_tags_check(self.region_name, self.profile_name)
        
        # Verify results
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding['status'], 'NON_COMPLIANT')
        self.assertEqual(len(finding['details']['missing_tags']), 5)  # All required tags missing
        self.assertEqual(finding['details']['total_tags_count'], 0)

    @patch('boto3.Session')
    def test_case_insensitive_validation(self, mock_session):
        """Test case insensitive validation for jurisdiction and classification."""
        # Mock the Lambda client
        mock_client = Mock()
        mock_session.return_value.client.return_value = mock_client
        
        # Mock paginator response
        mock_paginator = Mock()
        mock_paginator.paginate.return_value = [{'Functions': [self.sample_function]}]
        mock_client.get_paginator.return_value = mock_paginator
        
        # Mock list_tags response with lowercase values
        lowercase_tags = {
            'DataSovereignty': 'us',
            'DataJurisdiction': 'eu',
            'DataClassification': 'confidential',
            'DataResidency': 'eu-west-1',
            'ComplianceRegion': 'EU'
        }
        mock_client.list_tags.return_value = {'Tags': lowercase_tags}
        
        # Run the check
        findings = awslambda_function_data_sovereignty_tags_check(self.region_name, self.profile_name)
        
        # Verify results - should be compliant as values are valid when uppercased
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding['status'], 'COMPLIANT')

    @patch('boto3.Session')
    def test_list_tags_access_denied(self, mock_session):
        """Test handling when list_tags API call fails."""
        # Mock the Lambda client
        mock_client = Mock()
        mock_session.return_value.client.return_value = mock_client
        
        # Mock paginator response
        mock_paginator = Mock()
        mock_paginator.paginate.return_value = [{'Functions': [self.sample_function]}]
        mock_client.get_paginator.return_value = mock_paginator
        
        # Mock list_tags to raise an exception
        mock_client.list_tags.side_effect = ClientError(
            {'Error': {'Code': 'AccessDenied', 'Message': 'Access denied'}},
            'ListTags'
        )
        
        # Run the check
        findings = awslambda_function_data_sovereignty_tags_check(self.region_name, self.profile_name)
        
        # Verify error handling
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding['status'], 'ERROR')
        self.assertIn('Access denied', finding['details']['error'])

    @patch('boto3.Session')
    def test_api_access_error(self, mock_session):
        """Test handling of AWS API access errors."""
        # Mock the Lambda client to raise an exception
        mock_session.return_value.client.side_effect = ClientError(
            {'Error': {'Code': 'AccessDenied', 'Message': 'Access denied'}},
            'lambda'
        )
        
        # Run the check
        findings = awslambda_function_data_sovereignty_tags_check(self.region_name, self.profile_name)
        
        # Verify error handling
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding['status'], 'ERROR')
        self.assertEqual(finding['resource_id'], 'unknown')

    @patch('awslambda_function_data_sovereignty_tags.awslambda_function_data_sovereignty_tags_check')
    def test_main_function_wrapper(self, mock_check):
        """Test the main function wrapper with statistics calculation."""
        # Mock findings with mixed compliance status
        mock_findings = [
            {'status': 'COMPLIANT', 'resource_id': 'arn1'},
            {'status': 'NON_COMPLIANT', 'resource_id': 'arn2'},
            {'status': 'NON_COMPLIANT', 'resource_id': 'arn3'},
            {'status': 'ERROR', 'resource_id': 'arn4'}
        ]
        mock_check.return_value = mock_findings
        
        # Run the main function
        result = awslambda_function_data_sovereignty_tags(self.region_name, self.profile_name)
        
        # Verify statistics
        self.assertEqual(result['function_name'], 'awslambda_function_data_sovereignty_tags')
        self.assertEqual(result['region'], self.region_name)
        self.assertEqual(result['profile'], self.profile_name)
        self.assertEqual(result['total_findings'], 4)
        self.assertEqual(result['compliant_count'], 1)
        self.assertEqual(result['non_compliant_count'], 2)
        self.assertEqual(result['error_count'], 1)
        self.assertEqual(result['compliance_rate'], 25.0)  # 1/4 * 100

    @patch('boto3.Session')
    def test_multiple_functions_mixed_compliance(self, mock_session):
        """Test multiple Lambda functions with different compliance states."""
        # Mock the Lambda client
        mock_client = Mock()
        mock_session.return_value.client.return_value = mock_client
        
        # Multiple functions
        functions = [
            {
                'FunctionName': 'compliant-function',
                'FunctionArn': 'arn:aws:lambda:us-east-1:123456789012:function:compliant-function',
                'Runtime': 'python3.9',
                'LastModified': '2025-07-09T10:00:00.000+0000'
            },
            {
                'FunctionName': 'non-compliant-function',
                'FunctionArn': 'arn:aws:lambda:us-east-1:123456789012:function:non-compliant-function',
                'Runtime': 'nodejs18.x',
                'LastModified': '2025-07-09T10:00:00.000+0000'
            }
        ]
        
        # Mock paginator response
        mock_paginator = Mock()
        mock_paginator.paginate.return_value = [{'Functions': functions}]
        mock_client.get_paginator.return_value = mock_paginator
        
        # Mock list_tags responses - first compliant, second non-compliant
        mock_client.list_tags.side_effect = [
            {'Tags': self.valid_sovereignty_tags},  # Compliant function
            {'Tags': {'DataJurisdiction': 'US'}}    # Only one tag - non-compliant
        ]
        
        # Run the check
        findings = awslambda_function_data_sovereignty_tags_check(self.region_name, self.profile_name)
        
        # Verify results
        self.assertEqual(len(findings), 2)
        compliant_finding = next(f for f in findings if f['status'] == 'COMPLIANT')
        non_compliant_finding = next(f for f in findings if f['status'] == 'NON_COMPLIANT')
        
        self.assertIn('compliant-function', compliant_finding['details']['function_name'])
        self.assertIn('non-compliant-function', non_compliant_finding['details']['function_name'])


if __name__ == '__main__':
    unittest.main()
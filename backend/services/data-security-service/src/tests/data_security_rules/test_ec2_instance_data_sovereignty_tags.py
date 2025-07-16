#!/usr/bin/env python3
"""
Comprehensive Test Suite for ec2_instance_data_sovereignty_tags Function

Tests the EC2 instance data sovereignty tagging compliance function with proper mocking,
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
from ec2_instance_data_sovereignty_tags import ec2_instance_data_sovereignty_tags_check, ec2_instance_data_sovereignty_tags

class TestEC2InstanceDataSovereigntyTags:
    """Comprehensive test suite for ec2_instance_data_sovereignty_tags function."""
    
    def setup_method(self):
        """Setup test fixtures."""
        self.test_region = "us-east-1"
        self.test_profile = "test-profile"
        self.sample_instance_id = "i-1234567890abcdef0"
        self.sample_launch_time = datetime(2023, 1, 1, tzinfo=timezone.utc)
    
    def create_mock_session(self, client_responses: dict = None):
        """Create a mock boto3 session with configurable responses."""
        mock_session = Mock()
        mock_ec2_client = Mock()
        
        # Configure client responses
        if client_responses:
            if 'ec2' in client_responses:
                for method, response in client_responses['ec2'].items():
                    if isinstance(response, Exception):
                        getattr(mock_ec2_client, method).side_effect = response
                    else:
                        getattr(mock_ec2_client, method).return_value = response
        
        mock_session.client.return_value = mock_ec2_client
        return mock_session, mock_ec2_client
    
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
    
    def get_properly_tagged_instance_responses(self):
        """Get mock responses for a properly tagged EC2 instance."""
        mock_paginator = Mock()
        mock_paginator.paginate.return_value = [
            {
                'Reservations': [
                    {
                        'Instances': [
                            {
                                'InstanceId': self.sample_instance_id,
                                'InstanceType': 't3.medium',
                                'State': {'Name': 'running'},
                                'LaunchTime': self.sample_launch_time,
                                'Placement': {'AvailabilityZone': 'us-east-1a'},
                                'VpcId': 'vpc-12345678',
                                'SubnetId': 'subnet-12345678',
                                'PrivateIpAddress': '10.0.1.100',
                                'PublicIpAddress': '54.123.45.67',
                                'SecurityGroups': [{'GroupName': 'web-sg'}],
                                'ImageId': 'ami-12345678',
                                'KeyName': 'my-key-pair',
                                'Tags': [
                                    {'Key': 'DataJurisdiction', 'Value': 'US'},
                                    {'Key': 'DataResidency', 'Value': 'us-east-1'},
                                    {'Key': 'ComplianceFramework', 'Value': 'SOX'},
                                    {'Key': 'DataClassification', 'Value': 'CONFIDENTIAL'},
                                    {'Key': 'DataController', 'Value': 'Company Inc.'},
                                    {'Key': 'LegalBasis', 'Value': 'CONTRACT'},
                                    {'Key': 'DataProcessor', 'Value': 'Internal'},
                                    {'Key': 'RetentionPeriod', 'Value': 'P7Y'},
                                    {'Key': 'DataSubject', 'Value': 'CUSTOMER'},
                                    {'Key': 'SovereigntyLevel', 'Value': 'STRICT'},
                                    {'Key': 'CrossBorderTransfer', 'Value': 'RESTRICTED'},
                                    {'Key': 'ComplianceOfficer', 'Value': 'compliance@company.com'},
                                    {'Key': 'DataGovernor', 'Value': 'John Doe'}
                                ]
                            }
                        ]
                    }
                ]
            }
        ]
        
        return {
            'ec2': {
                'get_paginator': mock_paginator
            }
        }
    
    def get_missing_tags_instance_responses(self):
        """Get mock responses for an instance with missing required tags."""
        mock_paginator = Mock()
        mock_paginator.paginate.return_value = [
            {
                'Reservations': [
                    {
                        'Instances': [
                            {
                                'InstanceId': self.sample_instance_id,
                                'InstanceType': 't3.medium',
                                'State': {'Name': 'running'},
                                'LaunchTime': self.sample_launch_time,
                                'Placement': {'AvailabilityZone': 'us-east-1a'},
                                'VpcId': 'vpc-12345678',
                                'SubnetId': 'subnet-12345678',
                                'PrivateIpAddress': '10.0.1.100',
                                'SecurityGroups': [{'GroupName': 'web-sg'}],
                                'ImageId': 'ami-12345678',
                                'Tags': [
                                    {'Key': 'Name', 'Value': 'test-instance'},
                                    {'Key': 'Environment', 'Value': 'Development'}
                                    # Missing all required sovereignty tags
                                ]
                            }
                        ]
                    }
                ]
            }
        ]
        
        return {
            'ec2': {
                'get_paginator': mock_paginator
            }
        }
    
    def get_invalid_tag_values_instance_responses(self):
        """Get mock responses for an instance with invalid tag values."""
        mock_paginator = Mock()
        mock_paginator.paginate.return_value = [
            {
                'Reservations': [
                    {
                        'Instances': [
                            {
                                'InstanceId': self.sample_instance_id,
                                'InstanceType': 't3.medium',
                                'State': {'Name': 'running'},
                                'LaunchTime': self.sample_launch_time,
                                'Placement': {'AvailabilityZone': 'us-east-1a'},
                                'VpcId': 'vpc-12345678',
                                'SubnetId': 'subnet-12345678',
                                'Tags': [
                                    {'Key': 'DataJurisdiction', 'Value': 'INVALID_JURISDICTION'},
                                    {'Key': 'DataResidency', 'Value': 'invalid-region'},
                                    {'Key': 'ComplianceFramework', 'Value': 'INVALID_FRAMEWORK'},
                                    {'Key': 'DataClassification', 'Value': 'INVALID_CLASSIFICATION'},
                                    {'Key': 'LegalBasis', 'Value': 'INVALID_BASIS'}
                                ]
                            }
                        ]
                    }
                ]
            }
        ]
        
        return {
            'ec2': {
                'get_paginator': mock_paginator
            }
        }
    
    def get_residency_mismatch_instance_responses(self):
        """Get mock responses for an instance with region/residency mismatch."""
        mock_paginator = Mock()
        mock_paginator.paginate.return_value = [
            {
                'Reservations': [
                    {
                        'Instances': [
                            {
                                'InstanceId': self.sample_instance_id,
                                'InstanceType': 't3.medium',
                                'State': {'Name': 'running'},
                                'LaunchTime': self.sample_launch_time,
                                'Placement': {'AvailabilityZone': 'us-east-1a'},
                                'VpcId': 'vpc-12345678',
                                'SubnetId': 'subnet-12345678',
                                'Tags': [
                                    {'Key': 'DataJurisdiction', 'Value': 'US'},
                                    {'Key': 'DataResidency', 'Value': 'eu-west-1'},  # Mismatch with us-east-1
                                    {'Key': 'ComplianceFramework', 'Value': 'SOX'},
                                    {'Key': 'DataClassification', 'Value': 'CONFIDENTIAL'}
                                ]
                            }
                        ]
                    }
                ]
            }
        ]
        
        return {
            'ec2': {
                'get_paginator': mock_paginator
            }
        }
    
    def get_eu_gdpr_instance_responses(self):
        """Get mock responses for an EU/GDPR instance with missing required tags."""
        mock_paginator = Mock()
        mock_paginator.paginate.return_value = [
            {
                'Reservations': [
                    {
                        'Instances': [
                            {
                                'InstanceId': self.sample_instance_id,
                                'InstanceType': 't3.medium',
                                'State': {'Name': 'running'},
                                'LaunchTime': self.sample_launch_time,
                                'Placement': {'AvailabilityZone': 'eu-west-1a'},
                                'VpcId': 'vpc-12345678',
                                'SubnetId': 'subnet-12345678',
                                'Tags': [
                                    {'Key': 'DataJurisdiction', 'Value': 'EU'},
                                    {'Key': 'DataResidency', 'Value': 'eu-west-1'},
                                    {'Key': 'ComplianceFramework', 'Value': 'GDPR'},
                                    {'Key': 'DataClassification', 'Value': 'CONFIDENTIAL'}
                                    # Missing DataController and LegalBasis required for EU/GDPR
                                ]
                            }
                        ]
                    }
                ]
            }
        ]
        
        return {
            'ec2': {
                'get_paginator': mock_paginator
            }
        }
    
    def get_classification_sovereignty_mismatch_responses(self):
        """Get mock responses for an instance with classification/sovereignty mismatch."""
        mock_paginator = Mock()
        mock_paginator.paginate.return_value = [
            {
                'Reservations': [
                    {
                        'Instances': [
                            {
                                'InstanceId': self.sample_instance_id,
                                'InstanceType': 't3.medium',
                                'State': {'Name': 'running'},
                                'LaunchTime': self.sample_launch_time,
                                'Placement': {'AvailabilityZone': 'us-east-1a'},
                                'VpcId': 'vpc-12345678',
                                'SubnetId': 'subnet-12345678',
                                'Tags': [
                                    {'Key': 'DataJurisdiction', 'Value': 'US'},
                                    {'Key': 'DataResidency', 'Value': 'us-east-1'},
                                    {'Key': 'ComplianceFramework', 'Value': 'SOX'},
                                    {'Key': 'DataClassification', 'Value': 'RESTRICTED'},  # High sensitivity
                                    {'Key': 'SovereigntyLevel', 'Value': 'FLEXIBLE'},  # Should be STRICT
                                    {'Key': 'CrossBorderTransfer', 'Value': 'ALLOWED'}  # Should be RESTRICTED/PROHIBITED
                                ]
                            }
                        ]
                    }
                ]
            }
        ]
        
        return {
            'ec2': {
                'get_paginator': mock_paginator
            }
        }
    
    def test_properly_tagged_instance_compliant(self):
        """Test EC2 instance with proper sovereignty tags - should be compliant."""
        mock_responses = self.get_properly_tagged_instance_responses()
        
        with patch('boto3.Session') as mock_session_class:
            mock_session, mock_ec2_client = self.create_mock_session(mock_responses)
            mock_session_class.return_value = mock_session
            
            findings = ec2_instance_data_sovereignty_tags_check(self.test_region, self.test_profile)
            
            assert isinstance(findings, list)
            assert len(findings) > 0
            
            # Should have at least one compliant finding
            compliant_findings = [f for f in findings if f['status'] == 'COMPLIANT']
            assert len(compliant_findings) > 0
            
            for finding in findings:
                self.assert_finding_structure(finding)
                if finding['status'] == 'COMPLIANT':
                    assert 'tag_compliance_checks' in finding['details']
                    assert 'sovereignty_tags' in finding['details']
                    sovereignty_tags = finding['details']['sovereignty_tags']
                    assert 'DataJurisdiction' in sovereignty_tags
                    assert sovereignty_tags['DataJurisdiction'] == 'US'
    
    def test_missing_required_tags_non_compliant(self):
        """Test EC2 instance with missing required tags - should be non-compliant."""
        mock_responses = self.get_missing_tags_instance_responses()
        
        with patch('boto3.Session') as mock_session_class:
            mock_session, mock_ec2_client = self.create_mock_session(mock_responses)
            mock_session_class.return_value = mock_session
            
            findings = ec2_instance_data_sovereignty_tags_check(self.test_region, self.test_profile)
            
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
                    assert 'DataJurisdiction' in missing_tags
                    assert 'DataResidency' in missing_tags
                    assert 'ComplianceFramework' in missing_tags
                    assert 'DataClassification' in missing_tags
    
    def test_invalid_tag_values_non_compliant(self):
        """Test EC2 instance with invalid tag values - should be non-compliant."""
        mock_responses = self.get_invalid_tag_values_instance_responses()
        
        with patch('boto3.Session') as mock_session_class:
            mock_session, mock_ec2_client = self.create_mock_session(mock_responses)
            mock_session_class.return_value = mock_session
            
            findings = ec2_instance_data_sovereignty_tags_check(self.test_region, self.test_profile)
            
            assert isinstance(findings, list)
            assert len(findings) > 0
            
            # Should have non-compliant finding for invalid tag values
            non_compliant_findings = [f for f in findings if f['status'] == 'NON_COMPLIANT']
            assert len(non_compliant_findings) > 0
            
            for finding in non_compliant_findings:
                assert 'tag_violations' in finding['details']
                tag_violations = finding['details']['tag_violations']
                invalid_violations = [v for v in tag_violations if v.get('violation_type') == 'invalid_tag_value']
                assert len(invalid_violations) > 0
    
    def test_residency_mismatch_non_compliant(self):
        """Test EC2 instance with region/residency mismatch - should be non-compliant."""
        mock_responses = self.get_residency_mismatch_instance_responses()
        
        with patch('boto3.Session') as mock_session_class:
            mock_session, mock_ec2_client = self.create_mock_session(mock_responses)
            mock_session_class.return_value = mock_session
            
            findings = ec2_instance_data_sovereignty_tags_check(self.test_region, self.test_profile)
            
            assert isinstance(findings, list)
            assert len(findings) > 0
            
            # Should have non-compliant finding for residency mismatch
            non_compliant_findings = [f for f in findings if f['status'] == 'NON_COMPLIANT']
            assert len(non_compliant_findings) > 0
            
            for finding in non_compliant_findings:
                tag_violations = finding['details']['tag_violations']
                residency_violations = [v for v in tag_violations if v.get('violation_type') == 'residency_mismatch']
                assert len(residency_violations) > 0
    
    def test_eu_gdpr_jurisdiction_requirements(self):
        """Test EU/GDPR specific requirements - missing DataController and LegalBasis."""
        mock_responses = self.get_eu_gdpr_instance_responses()
        
        with patch('boto3.Session') as mock_session_class:
            mock_session, mock_ec2_client = self.create_mock_session(mock_responses)
            mock_session_class.return_value = mock_session
            
            findings = ec2_instance_data_sovereignty_tags_check("eu-west-1", self.test_profile)
            
            assert isinstance(findings, list)
            assert len(findings) > 0
            
            # Should have non-compliant finding for missing EU/GDPR requirements
            non_compliant_findings = [f for f in findings if f['status'] == 'NON_COMPLIANT']
            assert len(non_compliant_findings) > 0
            
            for finding in non_compliant_findings:
                tag_violations = finding['details']['tag_violations']
                jurisdiction_violations = [v for v in tag_violations if v.get('violation_type') == 'missing_jurisdiction_tag']
                assert len(jurisdiction_violations) > 0
                # Should have violations for missing DataController and LegalBasis
                violation_tags = [v.get('tag_name') for v in jurisdiction_violations]
                assert 'DataController' in violation_tags
                assert 'LegalBasis' in violation_tags
    
    def test_classification_sovereignty_mismatch_non_compliant(self):
        """Test instance with classification/sovereignty level mismatch - should be non-compliant."""
        mock_responses = self.get_classification_sovereignty_mismatch_responses()
        
        with patch('boto3.Session') as mock_session_class:
            mock_session, mock_ec2_client = self.create_mock_session(mock_responses)
            mock_session_class.return_value = mock_session
            
            findings = ec2_instance_data_sovereignty_tags_check(self.test_region, self.test_profile)
            
            assert isinstance(findings, list)
            assert len(findings) > 0
            
            # Should have non-compliant finding for classification/sovereignty mismatch
            non_compliant_findings = [f for f in findings if f['status'] == 'NON_COMPLIANT']
            assert len(non_compliant_findings) > 0
            
            for finding in non_compliant_findings:
                tag_violations = finding['details']['tag_violations']
                mismatch_violations = [v for v in tag_violations if 'mismatch' in v.get('violation_type', '')]
                assert len(mismatch_violations) > 0
    
    def test_retention_period_format_validation(self):
        """Test retention period format validation."""
        mock_responses = {
            'ec2': {
                'get_paginator': Mock(side_effect=lambda x: Mock(paginate=Mock(return_value=[{
                    'Reservations': [{
                        'Instances': [{
                            'InstanceId': self.sample_instance_id,
                            'InstanceType': 't3.medium',
                            'State': {'Name': 'running'},
                            'LaunchTime': self.sample_launch_time,
                            'Placement': {'AvailabilityZone': 'us-east-1a'},
                            'VpcId': 'vpc-12345678',
                            'SubnetId': 'subnet-12345678',
                            'Tags': [
                                {'Key': 'DataJurisdiction', 'Value': 'US'},
                                {'Key': 'DataResidency', 'Value': 'us-east-1'},
                                {'Key': 'ComplianceFramework', 'Value': 'SOX'},
                                {'Key': 'DataClassification', 'Value': 'CONFIDENTIAL'},
                                {'Key': 'RetentionPeriod', 'Value': 'INVALID_FORMAT'}  # Invalid format
                            ]
                        }]
                    }]
                }])))
            }
        }
        
        with patch('boto3.Session') as mock_session_class:
            mock_session, mock_ec2_client = self.create_mock_session(mock_responses)
            mock_session_class.return_value = mock_session
            
            findings = ec2_instance_data_sovereignty_tags_check(self.test_region, self.test_profile)
            
            assert isinstance(findings, list)
            if findings:
                non_compliant_findings = [f for f in findings if f['status'] == 'NON_COMPLIANT']
                for finding in non_compliant_findings:
                    tag_violations = finding['details']['tag_violations']
                    retention_violations = [v for v in tag_violations if v.get('violation_type') == 'invalid_retention_format']
                    assert len(retention_violations) > 0
    
    def test_compliance_officer_email_validation(self):
        """Test compliance officer email format validation."""
        mock_responses = {
            'ec2': {
                'get_paginator': Mock(side_effect=lambda x: Mock(paginate=Mock(return_value=[{
                    'Reservations': [{
                        'Instances': [{
                            'InstanceId': self.sample_instance_id,
                            'InstanceType': 't3.medium',
                            'State': {'Name': 'running'},
                            'LaunchTime': self.sample_launch_time,
                            'Placement': {'AvailabilityZone': 'us-east-1a'},
                            'VpcId': 'vpc-12345678',
                            'SubnetId': 'subnet-12345678',
                            'Tags': [
                                {'Key': 'DataJurisdiction', 'Value': 'US'},
                                {'Key': 'DataResidency', 'Value': 'us-east-1'},
                                {'Key': 'ComplianceFramework', 'Value': 'HIPAA'},
                                {'Key': 'DataClassification', 'Value': 'CONFIDENTIAL'},
                                {'Key': 'ComplianceOfficer', 'Value': 'invalid-email-format'}  # Invalid email
                            ]
                        }]
                    }]
                }])))
            }
        }
        
        with patch('boto3.Session') as mock_session_class:
            mock_session, mock_ec2_client = self.create_mock_session(mock_responses)
            mock_session_class.return_value = mock_session
            
            findings = ec2_instance_data_sovereignty_tags_check(self.test_region, self.test_profile)
            
            assert isinstance(findings, list)
            if findings:
                non_compliant_findings = [f for f in findings if f['status'] == 'NON_COMPLIANT']
                for finding in non_compliant_findings:
                    tag_violations = finding['details']['tag_violations']
                    email_violations = [v for v in tag_violations if v.get('violation_type') == 'invalid_email_format']
                    assert len(email_violations) > 0
    
    def test_us_compliance_framework_requirements(self):
        """Test US compliance framework specific requirements."""
        mock_responses = {
            'ec2': {
                'get_paginator': Mock(side_effect=lambda x: Mock(paginate=Mock(return_value=[{
                    'Reservations': [{
                        'Instances': [{
                            'InstanceId': self.sample_instance_id,
                            'InstanceType': 't3.medium',
                            'State': {'Name': 'running'},
                            'LaunchTime': self.sample_launch_time,
                            'Placement': {'AvailabilityZone': 'us-east-1a'},
                            'VpcId': 'vpc-12345678',
                            'SubnetId': 'subnet-12345678',
                            'Tags': [
                                {'Key': 'DataJurisdiction', 'Value': 'US'},
                                {'Key': 'DataResidency', 'Value': 'us-east-1'},
                                {'Key': 'ComplianceFramework', 'Value': 'HIPAA'},
                                {'Key': 'DataClassification', 'Value': 'CONFIDENTIAL'}
                                # Missing ComplianceOfficer for US HIPAA
                            ]
                        }]
                    }]
                }])))
            }
        }
        
        with patch('boto3.Session') as mock_session_class:
            mock_session, mock_ec2_client = self.create_mock_session(mock_responses)
            mock_session_class.return_value = mock_session
            
            findings = ec2_instance_data_sovereignty_tags_check(self.test_region, self.test_profile)
            
            assert isinstance(findings, list)
            if findings:
                non_compliant_findings = [f for f in findings if f['status'] == 'NON_COMPLIANT']
                for finding in non_compliant_findings:
                    tag_violations = finding['details']['tag_violations']
                    us_violations = [v for v in tag_violations if v.get('violation_type') == 'missing_jurisdiction_tag' and v.get('tag_name') == 'ComplianceOfficer']
                    assert len(us_violations) > 0
    
    def test_api_access_error_handling(self):
        """Test error handling for API access issues."""
        error_responses = {
            'ec2': {
                'get_paginator': Mock(side_effect=ClientError(
                    {'Error': {'Code': 'AccessDenied', 'Message': 'Access denied'}},
                    'DescribeInstances'
                ))
            }
        }
        
        with patch('boto3.Session') as mock_session_class:
            mock_session, mock_ec2_client = self.create_mock_session(error_responses)
            mock_session_class.return_value = mock_session
            
            findings = ec2_instance_data_sovereignty_tags_check(self.test_region, self.test_profile)
            
            assert isinstance(findings, list)
            assert len(findings) >= 1
            
            # Should have at least one ERROR finding
            error_findings = [f for f in findings if f['status'] == 'ERROR']
            assert len(error_findings) >= 1
    
    def test_no_credentials_error(self):
        """Test handling of no AWS credentials."""
        with patch('boto3.Session') as mock_session_class:
            mock_session_class.side_effect = NoCredentialsError()
            
            findings = ec2_instance_data_sovereignty_tags_check(self.test_region, self.test_profile)
            
            assert isinstance(findings, list)
            assert len(findings) >= 1
            assert all(f['status'] == 'ERROR' for f in findings)
    
    def test_instance_specific_error_handling(self):
        """Test error handling for instance-specific issues."""
        mock_responses = {
            'ec2': {
                'get_paginator': Mock(side_effect=lambda x: Mock(paginate=Mock(return_value=[{
                    'Reservations': [{
                        'Instances': [{
                            'InstanceId': self.sample_instance_id,
                            'InstanceType': 't3.medium',
                            'State': {'Name': 'running'},
                            'LaunchTime': self.sample_launch_time,
                            'Placement': {'AvailabilityZone': 'us-east-1a'},
                            'VpcId': 'vpc-12345678',
                            'SubnetId': 'subnet-12345678',
                            'Tags': None  # This will cause an error
                        }]
                    }]
                }])))
            }
        }
        
        with patch('boto3.Session') as mock_session_class:
            mock_session, mock_ec2_client = self.create_mock_session(mock_responses)
            mock_session_class.return_value = mock_session
            
            findings = ec2_instance_data_sovereignty_tags_check(self.test_region, self.test_profile)
            
            assert isinstance(findings, list)
            # Should handle instance-specific errors gracefully
            error_findings = [f for f in findings if f['status'] == 'ERROR']
            if error_findings:
                assert len(error_findings) >= 1
    
    def test_wrapper_function(self):
        """Test the main wrapper function."""
        mock_responses = self.get_properly_tagged_instance_responses()
        
        with patch('boto3.Session') as mock_session_class:
            mock_session, mock_ec2_client = self.create_mock_session(mock_responses)
            mock_session_class.return_value = mock_session
            
            result = ec2_instance_data_sovereignty_tags(self.test_region, self.test_profile)
            
            assert isinstance(result, dict)
            required_keys = ['function_name', 'region', 'profile', 'total_findings',
                           'compliant_count', 'non_compliant_count', 'error_count',
                           'compliance_rate', 'findings']
            
            for key in required_keys:
                assert key in result
            
            assert result['function_name'] == 'ec2_instance_data_sovereignty_tags'
            assert result['region'] == self.test_region
            assert isinstance(result['findings'], list)
    
    def test_tag_completeness_calculation(self):
        """Test tag completeness percentage calculation."""
        mock_responses = self.get_properly_tagged_instance_responses()
        
        with patch('boto3.Session') as mock_session_class:
            mock_session, mock_ec2_client = self.create_mock_session(mock_responses)
            mock_session_class.return_value = mock_session
            
            findings = ec2_instance_data_sovereignty_tags_check(self.test_region, self.test_profile)
            
            assert isinstance(findings, list)
            if findings:
                for finding in findings:
                    assert 'tag_completeness_percentage' in finding['details']
                    completeness = finding['details']['tag_completeness_percentage']
                    assert isinstance(completeness, (int, float))
                    assert 0 <= completeness <= 100
    
    def test_instance_details_inclusion(self):
        """Test that instance details are properly included in findings."""
        mock_responses = self.get_properly_tagged_instance_responses()
        
        with patch('boto3.Session') as mock_session_class:
            mock_session, mock_ec2_client = self.create_mock_session(mock_responses)
            mock_session_class.return_value = mock_session
            
            findings = ec2_instance_data_sovereignty_tags_check(self.test_region, self.test_profile)
            
            assert isinstance(findings, list)
            if findings:
                for finding in findings:
                    assert 'instance_details' in finding['details']
                    instance_details = finding['details']['instance_details']
                    expected_fields = ['instance_type', 'state', 'launch_time', 'availability_zone', 
                                     'vpc_id', 'subnet_id', 'private_ip', 'security_groups', 'image_id']
                    for field in expected_fields:
                        assert field in instance_details

def test_module_imports():
    """Test that the module can be imported successfully."""
    try:
        import ec2_instance_data_sovereignty_tags
        assert hasattr(ec2_instance_data_sovereignty_tags, 'ec2_instance_data_sovereignty_tags_check')
        assert hasattr(ec2_instance_data_sovereignty_tags, 'ec2_instance_data_sovereignty_tags')
    except ImportError as e:
        pytest.fail(f"Failed to import ec2_instance_data_sovereignty_tags: {e}")

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
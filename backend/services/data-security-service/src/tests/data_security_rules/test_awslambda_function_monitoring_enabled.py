#!/usr/bin/env python3
"""
Comprehensive Test Suite for awslambda_function_monitoring_enabled Function

Tests the AWS Lambda function monitoring compliance function with proper mocking,
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
from awslambda_function_monitoring_enabled import awslambda_function_monitoring_enabled_check, awslambda_function_monitoring_enabled

class TestAWSLambdaFunctionMonitoringEnabled:
    """Comprehensive test suite for awslambda_function_monitoring_enabled function."""
    
    def setup_method(self):
        """Setup test fixtures."""
        self.test_region = "us-east-1"
        self.test_profile = "test-profile"
        self.sample_function_name = "test-lambda-function"
        self.sample_function_arn = f"arn:aws:lambda:{self.test_region}:123456789012:function:{self.sample_function_name}"
    
    def create_mock_session(self, client_responses: dict = None):
        """Create a mock boto3 session with configurable responses."""
        mock_session = Mock()
        
        # Mock different clients
        mock_lambda_client = Mock()
        mock_cloudwatch_client = Mock()
        mock_logs_client = Mock()
        
        # Configure client responses
        if client_responses:
            if 'lambda' in client_responses:
                for method, response in client_responses['lambda'].items():
                    if isinstance(response, Exception):
                        getattr(mock_lambda_client, method).side_effect = response
                    else:
                        getattr(mock_lambda_client, method).return_value = response
            
            if 'cloudwatch' in client_responses:
                for method, response in client_responses['cloudwatch'].items():
                    if isinstance(response, Exception):
                        getattr(mock_cloudwatch_client, method).side_effect = response
                    else:
                        getattr(mock_cloudwatch_client, method).return_value = response
            
            if 'logs' in client_responses:
                for method, response in client_responses['logs'].items():
                    if isinstance(response, Exception):
                        getattr(mock_logs_client, method).side_effect = response
                    else:
                        getattr(mock_logs_client, method).return_value = response
        
        # Configure session.client to return appropriate mock client
        def client_factory(service_name, **kwargs):
            if service_name == 'lambda':
                return mock_lambda_client
            elif service_name == 'cloudwatch':
                return mock_cloudwatch_client
            elif service_name == 'logs':
                return mock_logs_client
            else:
                return Mock()
        
        mock_session.client.side_effect = client_factory
        return mock_session, {
            'lambda': mock_lambda_client,
            'cloudwatch': mock_cloudwatch_client,
            'logs': mock_logs_client
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
    
    def get_fully_monitored_lambda_responses(self):
        """Get mock responses for a fully monitored Lambda function."""
        mock_paginator = Mock()
        mock_paginator.paginate.return_value = [
            {
                'Functions': [
                    {
                        'FunctionName': self.sample_function_name,
                        'FunctionArn': self.sample_function_arn,
                        'Runtime': 'python3.9',
                        'LastModified': '2023-01-01T00:00:00.000+0000'
                    }
                ]
            }
        ]
        
        return {
            'lambda': {
                'get_paginator': mock_paginator,
                'get_function': {
                    'Configuration': {
                        'FunctionName': self.sample_function_name,
                        'FunctionArn': self.sample_function_arn,
                        'TracingConfig': {
                            'Mode': 'Active'  # X-Ray enabled
                        },
                        'Environment': {
                            'Variables': {
                                'LOG_LEVEL': 'DEBUG',
                                'MONITORING_ENABLED': 'true'
                            }
                        },
                        'Layers': [
                            {
                                'Arn': 'arn:aws:lambda:us-east-1:580247275435:layer:LambdaInsightsExtension:14'
                            }
                        ],
                        'DeadLetterConfig': {
                            'TargetArn': 'arn:aws:sqs:us-east-1:123456789012:dlq'
                        },
                        'Timeout': 30
                    }
                }
            },
            'logs': {
                'describe_log_groups': {
                    'logGroups': [
                        {
                            'logGroupName': f'/aws/lambda/{self.sample_function_name}',
                            'retentionInDays': 14
                        }
                    ]
                }
            },
            'cloudwatch': {
                'describe_alarms': {
                    'MetricAlarms': [
                        {
                            'AlarmName': f'{self.sample_function_name}-errors',
                            'StateValue': 'OK',
                            'MetricName': 'Errors',
                            'AlarmActions': [self.sample_function_arn]
                        }
                    ]
                }
            }
        }
    
    def get_poorly_monitored_lambda_responses(self):
        """Get mock responses for a poorly monitored Lambda function."""
        mock_paginator = Mock()
        mock_paginator.paginate.return_value = [
            {
                'Functions': [
                    {
                        'FunctionName': self.sample_function_name,
                        'FunctionArn': self.sample_function_arn,
                        'Runtime': 'python3.9',
                        'LastModified': '2023-01-01T00:00:00.000+0000'
                    }
                ]
            }
        ]
        
        return {
            'lambda': {
                'get_paginator': mock_paginator,
                'get_function': {
                    'Configuration': {
                        'FunctionName': self.sample_function_name,
                        'FunctionArn': self.sample_function_arn,
                        'TracingConfig': {
                            'Mode': 'PassThrough'  # X-Ray disabled
                        },
                        'Environment': {
                            'Variables': {
                                'APP_ENV': 'production'  # No monitoring vars
                            }
                        },
                        'Layers': [],  # No Lambda Insights
                        'Timeout': 900  # Very high timeout
                        # No DeadLetterConfig
                    }
                }
            },
            'logs': {
                'describe_log_groups': {
                    'logGroups': [
                        {
                            'logGroupName': f'/aws/lambda/{self.sample_function_name}'
                            # No retentionInDays
                        }
                    ]
                }
            },
            'cloudwatch': {
                'describe_alarms': {
                    'MetricAlarms': []  # No alarms
                }
            }
        }
    
    def get_no_logs_lambda_responses(self):
        """Get mock responses for a Lambda function without log group."""
        mock_paginator = Mock()
        mock_paginator.paginate.return_value = [
            {
                'Functions': [
                    {
                        'FunctionName': self.sample_function_name,
                        'FunctionArn': self.sample_function_arn,
                        'Runtime': 'python3.9',
                        'LastModified': '2023-01-01T00:00:00.000+0000'
                    }
                ]
            }
        ]
        
        return {
            'lambda': {
                'get_paginator': mock_paginator,
                'get_function': {
                    'Configuration': {
                        'FunctionName': self.sample_function_name,
                        'FunctionArn': self.sample_function_arn,
                        'TracingConfig': {
                            'Mode': 'PassThrough'
                        },
                        'Environment': {'Variables': {}},
                        'Layers': [],
                        'Timeout': 30
                    }
                }
            },
            'logs': {
                'describe_log_groups': {
                    'logGroups': []  # No log group exists
                }
            },
            'cloudwatch': {
                'describe_alarms': {
                    'MetricAlarms': []
                }
            }
        }
    
    def test_fully_monitored_lambda_compliant(self):
        """Test Lambda function with full monitoring - should be compliant."""
        mock_responses = self.get_fully_monitored_lambda_responses()
        
        with patch('boto3.Session') as mock_session_class:
            mock_session, mock_clients = self.create_mock_session(mock_responses)
            mock_session_class.return_value = mock_session
            
            findings = awslambda_function_monitoring_enabled_check(self.test_region, self.test_profile)
            
            assert isinstance(findings, list)
            assert len(findings) > 0
            
            # Should have at least one compliant finding
            compliant_findings = [f for f in findings if f['status'] == 'COMPLIANT']
            assert len(compliant_findings) > 0
            
            for finding in findings:
                self.assert_finding_structure(finding)
                if finding['status'] == 'COMPLIANT':
                    assert 'configured_monitoring' in finding['details']
                    assert finding['details']['tracing_mode'] == 'Active'
                    assert finding['details']['monitoring_score'] >= 3
    
    def test_poorly_monitored_lambda_non_compliant(self):
        """Test Lambda function with poor monitoring - should be non-compliant."""
        mock_responses = self.get_poorly_monitored_lambda_responses()
        
        with patch('boto3.Session') as mock_session_class:
            mock_session, mock_clients = self.create_mock_session(mock_responses)
            mock_session_class.return_value = mock_session
            
            findings = awslambda_function_monitoring_enabled_check(self.test_region, self.test_profile)
            
            assert isinstance(findings, list)
            assert len(findings) > 0
            
            # Should have at least one non-compliant finding
            non_compliant_findings = [f for f in findings if f['status'] == 'NON_COMPLIANT']
            assert len(non_compliant_findings) > 0
            
            for finding in findings:
                self.assert_finding_structure(finding)
                if finding['status'] == 'NON_COMPLIANT':
                    assert 'monitoring_violations' in finding['details']
                    assert finding['details']['tracing_mode'] == 'PassThrough'
                    violations = finding['details']['monitoring_violations']
                    assert any('X-Ray tracing' in v for v in violations)
    
    def test_lambda_without_log_group_non_compliant(self):
        """Test Lambda function without log group - should be non-compliant."""
        mock_responses = self.get_no_logs_lambda_responses()
        
        with patch('boto3.Session') as mock_session_class:
            mock_session, mock_clients = self.create_mock_session(mock_responses)
            mock_session_class.return_value = mock_session
            
            findings = awslambda_function_monitoring_enabled_check(self.test_region, self.test_profile)
            
            assert isinstance(findings, list)
            assert len(findings) > 0
            
            # Should have non-compliant finding for missing log group
            non_compliant_findings = [f for f in findings if f['status'] == 'NON_COMPLIANT']
            assert len(non_compliant_findings) > 0
            
            for finding in non_compliant_findings:
                violations = finding['details']['monitoring_violations']
                assert any('CloudWatch Logs group does not exist' in v for v in violations)
    
    def test_lambda_insights_layer_detection(self):
        """Test detection of Lambda Insights layer."""
        mock_responses = self.get_fully_monitored_lambda_responses()
        
        with patch('boto3.Session') as mock_session_class:
            mock_session, mock_clients = self.create_mock_session(mock_responses)
            mock_session_class.return_value = mock_session
            
            findings = awslambda_function_monitoring_enabled_check(self.test_region, self.test_profile)
            
            assert isinstance(findings, list)
            if findings:
                compliant_findings = [f for f in findings if f['status'] == 'COMPLIANT']
                for finding in compliant_findings:
                    monitoring_features = finding['details']['configured_monitoring']
                    insights_features = [f for f in monitoring_features if f['feature'] == 'Lambda Insights']
                    assert len(insights_features) > 0
    
    def test_environment_variables_monitoring_detection(self):
        """Test detection of monitoring-related environment variables."""
        mock_responses = self.get_fully_monitored_lambda_responses()
        
        with patch('boto3.Session') as mock_session_class:
            mock_session, mock_clients = self.create_mock_session(mock_responses)
            mock_session_class.return_value = mock_session
            
            findings = awslambda_function_monitoring_enabled_check(self.test_region, self.test_profile)
            
            assert isinstance(findings, list)
            if findings:
                compliant_findings = [f for f in findings if f['status'] == 'COMPLIANT']
                for finding in compliant_findings:
                    monitoring_features = finding['details']['configured_monitoring']
                    env_features = [f for f in monitoring_features if f['feature'] == 'Monitoring Environment Variables']
                    assert len(env_features) > 0
                    assert 'LOG_LEVEL' in env_features[0]['variables']
    
    def test_dead_letter_queue_detection(self):
        """Test detection of dead letter queue configuration."""
        mock_responses = self.get_fully_monitored_lambda_responses()
        
        with patch('boto3.Session') as mock_session_class:
            mock_session, mock_clients = self.create_mock_session(mock_responses)
            mock_session_class.return_value = mock_session
            
            findings = awslambda_function_monitoring_enabled_check(self.test_region, self.test_profile)
            
            assert isinstance(findings, list)
            if findings:
                compliant_findings = [f for f in findings if f['status'] == 'COMPLIANT']
                for finding in compliant_findings:
                    monitoring_features = finding['details']['configured_monitoring']
                    dlq_features = [f for f in monitoring_features if f['feature'] == 'Dead Letter Queue']
                    assert len(dlq_features) > 0
    
    def test_high_timeout_violation(self):
        """Test that very high timeout is flagged as a violation."""
        mock_responses = self.get_poorly_monitored_lambda_responses()
        
        with patch('boto3.Session') as mock_session_class:
            mock_session, mock_clients = self.create_mock_session(mock_responses)
            mock_session_class.return_value = mock_session
            
            findings = awslambda_function_monitoring_enabled_check(self.test_region, self.test_profile)
            
            assert isinstance(findings, list)
            if findings:
                non_compliant_findings = [f for f in findings if f['status'] == 'NON_COMPLIANT']
                for finding in non_compliant_findings:
                    violations = finding['details']['monitoring_violations']
                    timeout_violations = [v for v in violations if 'timeout too high' in v.lower()]
                    assert len(timeout_violations) > 0
    
    def test_cloudwatch_logs_retention_check(self):
        """Test CloudWatch Logs retention configuration check."""
        mock_responses = self.get_poorly_monitored_lambda_responses()
        
        with patch('boto3.Session') as mock_session_class:
            mock_session, mock_clients = self.create_mock_session(mock_responses)
            mock_session_class.return_value = mock_session
            
            findings = awslambda_function_monitoring_enabled_check(self.test_region, self.test_profile)
            
            assert isinstance(findings, list)
            if findings:
                non_compliant_findings = [f for f in findings if f['status'] == 'NON_COMPLIANT']
                for finding in non_compliant_findings:
                    violations = finding['details']['monitoring_violations']
                    retention_violations = [v for v in violations if 'retention' in v.lower()]
                    assert len(retention_violations) > 0
    
    def test_api_access_error_handling(self):
        """Test error handling for API access issues."""
        error_responses = {
            'lambda': {
                'get_paginator': Mock(side_effect=ClientError(
                    {'Error': {'Code': 'AccessDenied', 'Message': 'Access denied'}},
                    'ListFunctions'
                ))
            }
        }
        
        with patch('boto3.Session') as mock_session_class:
            mock_session, mock_clients = self.create_mock_session(error_responses)
            mock_session_class.return_value = mock_session
            
            findings = awslambda_function_monitoring_enabled_check(self.test_region, self.test_profile)
            
            assert isinstance(findings, list)
            assert len(findings) >= 1
            
            # Should have at least one ERROR finding
            error_findings = [f for f in findings if f['status'] == 'ERROR']
            assert len(error_findings) >= 1
    
    def test_no_credentials_error(self):
        """Test handling of no AWS credentials."""
        with patch('boto3.Session') as mock_session_class:
            mock_session_class.side_effect = NoCredentialsError()
            
            findings = awslambda_function_monitoring_enabled_check(self.test_region, self.test_profile)
            
            assert isinstance(findings, list)
            assert len(findings) >= 1
            assert all(f['status'] == 'ERROR' for f in findings)
    
    def test_function_specific_error_handling(self):
        """Test error handling for function-specific issues."""
        mock_paginator = Mock()
        mock_paginator.paginate.return_value = [
            {
                'Functions': [
                    {
                        'FunctionName': self.sample_function_name,
                        'FunctionArn': self.sample_function_arn
                    }
                ]
            }
        ]
        
        mock_responses = {
            'lambda': {
                'get_paginator': mock_paginator,
                'get_function': ClientError(
                    {'Error': {'Code': 'ResourceNotFoundException'}},
                    'GetFunction'
                )
            }
        }
        
        with patch('boto3.Session') as mock_session_class:
            mock_session, mock_clients = self.create_mock_session(mock_responses)
            mock_session_class.return_value = mock_session
            
            findings = awslambda_function_monitoring_enabled_check(self.test_region, self.test_profile)
            
            assert isinstance(findings, list)
            # Should handle function-specific errors gracefully
            error_findings = [f for f in findings if f['status'] == 'ERROR']
            if error_findings:
                assert len(error_findings) >= 1
    
    def test_wrapper_function(self):
        """Test the main wrapper function."""
        mock_responses = self.get_fully_monitored_lambda_responses()
        
        with patch('boto3.Session') as mock_session_class:
            mock_session, mock_clients = self.create_mock_session(mock_responses)
            mock_session_class.return_value = mock_session
            
            result = awslambda_function_monitoring_enabled(self.test_region, self.test_profile)
            
            assert isinstance(result, dict)
            required_keys = ['function_name', 'region', 'profile', 'total_findings',
                           'compliant_count', 'non_compliant_count', 'error_count',
                           'compliance_rate', 'findings']
            
            for key in required_keys:
                assert key in result
            
            assert result['function_name'] == 'awslambda_function_monitoring_enabled'
            assert result['region'] == self.test_region
            assert isinstance(result['findings'], list)
    
    def test_mixed_monitoring_scenarios(self):
        """Test multiple Lambda functions with different monitoring configurations."""
        mock_paginator = Mock()
        mock_paginator.paginate.return_value = [
            {
                'Functions': [
                    {
                        'FunctionName': 'well-monitored-function',
                        'FunctionArn': 'arn:aws:lambda:us-east-1:123456789012:function:well-monitored-function'
                    },
                    {
                        'FunctionName': 'poorly-monitored-function',
                        'FunctionArn': 'arn:aws:lambda:us-east-1:123456789012:function:poorly-monitored-function'
                    }
                ]
            }
        ]
        
        # Mock function configuration responses based on function name
        def get_function_side_effect(*args, **kwargs):
            function_name = kwargs.get('FunctionName', '')
            if 'well-monitored' in function_name:
                return {
                    'Configuration': {
                        'FunctionName': function_name,
                        'TracingConfig': {'Mode': 'Active'},
                        'Environment': {'Variables': {'LOG_LEVEL': 'DEBUG'}},
                        'Layers': [{'Arn': 'arn:aws:lambda:us-east-1:580247275435:layer:LambdaInsightsExtension:14'}],
                        'DeadLetterConfig': {'TargetArn': 'arn:aws:sqs:us-east-1:123456789012:dlq'},
                        'Timeout': 30
                    }
                }
            else:
                return {
                    'Configuration': {
                        'FunctionName': function_name,
                        'TracingConfig': {'Mode': 'PassThrough'},
                        'Environment': {'Variables': {}},
                        'Layers': [],
                        'Timeout': 900
                    }
                }
        
        mock_responses = {
            'lambda': {
                'get_paginator': mock_paginator
            },
            'logs': {
                'describe_log_groups': {'logGroups': []}
            },
            'cloudwatch': {
                'describe_alarms': {'MetricAlarms': []}
            }
        }
        
        with patch('boto3.Session') as mock_session_class:
            mock_session, mock_clients = self.create_mock_session(mock_responses)
            mock_clients['lambda'].get_function.side_effect = get_function_side_effect
            mock_session_class.return_value = mock_session
            
            findings = awslambda_function_monitoring_enabled_check(self.test_region, self.test_profile)
            
            assert isinstance(findings, list)
            assert len(findings) >= 2  # Should have findings for both functions
            
            # Should have a mix of compliance statuses
            statuses = [f['status'] for f in findings]
            unique_statuses = set(statuses)
            assert len(unique_statuses) > 1  # Should have different statuses

def test_module_imports():
    """Test that the module can be imported successfully."""
    try:
        import awslambda_function_monitoring_enabled
        assert hasattr(awslambda_function_monitoring_enabled, 'awslambda_function_monitoring_enabled_check')
        assert hasattr(awslambda_function_monitoring_enabled, 'awslambda_function_monitoring_enabled')
    except ImportError as e:
        pytest.fail(f"Failed to import awslambda_function_monitoring_enabled: {e}")

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
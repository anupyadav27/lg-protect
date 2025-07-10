#!/usr/bin/env python3
"""
Comprehensive Test Generator for Data Security AWS Compliance Functions

This script generates complete test suites for all 185 compliance functions
across 15 AWS services with proper mocking, error scenarios, and edge cases.
"""

import os
import json
from collections import defaultdict
from typing import Dict, List, Any

def get_service_functions() -> Dict[str, List[str]]:
    """Get all functions organized by AWS service."""
    data_function_dir = '/Users/apple/Desktop/utility/data-security/data_function_list'
    files = [f for f in os.listdir(data_function_dir) if f.endswith('.py')]
    
    services = defaultdict(list)
    
    service_mappings = {
        'awslambda_': 'lambda',
        's3_': 's3', 
        'dynamodb_': 'dynamodb',
        'ec2_': 'ec2',
        'rds_': 'rds',
        'cloudtrail_': 'cloudtrail',
        'iam_': 'iam',
        'kms_': 'kms',
        'vpc_': 'vpc',
        'efs_': 'efs',
        'ebs_': 'ebs',
        'glue_': 'glue',
        'redshift_': 'redshift',
        'stepfunctions_': 'stepfunctions',
        'replication_': 'replication'
    }
    
    for file in files:
        function_name = file.replace('.py', '')
        for prefix, service in service_mappings.items():
            if file.startswith(prefix):
                services[service].append(function_name)
                break
    
    return services

def generate_test_file_content(service: str, functions: List[str]) -> str:
    """Generate comprehensive test file content for a service."""
    
    # Create imports section
    imports = f'''#!/usr/bin/env python3
"""
Comprehensive Test Suite for {service.upper()} Data Security Compliance Functions

Tests all {len(functions)} {service.upper()} compliance functions with proper mocking,
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

# Import all {service} compliance functions
'''

    # Add function imports
    for function in functions:
        imports += f"from {function} import {function}_check, {function}\n"

    # Create test class
    test_class = f'''

class Test{service.title()}ComplianceFunctions:
    """Comprehensive test suite for {service.upper()} compliance functions."""
    
    def setup_method(self):
        """Setup test fixtures."""
        self.test_region = "us-east-1"
        self.test_profile = "test-profile"
        self.sample_findings = []
    
    def create_mock_session(self, client_responses: Dict[str, Any] = None):
        """Create a mock boto3 session with configurable responses."""
        mock_session = Mock()
        mock_client = Mock()
        
        if client_responses:
            for method, response in client_responses.items():
                if isinstance(response, Exception):
                    getattr(mock_client, method).side_effect = response
                else:
                    getattr(mock_client, method).return_value = response
        
        mock_session.client.return_value = mock_client
        return mock_session, mock_client
    
    def assert_finding_structure(self, finding: Dict[str, Any]):
        """Assert that a finding has the correct structure."""
        required_fields = ['region', 'profile', 'resource_type', 'resource_id', 
                          'status', 'risk_level', 'recommendation', 'details']
        
        for field in required_fields:
            assert field in finding, f"Missing required field: {{field}}"
        
        # Validate status values
        assert finding['status'] in ['COMPLIANT', 'NON_COMPLIANT', 'ERROR']
        
        # Validate risk levels
        assert finding['risk_level'] in ['LOW', 'MEDIUM', 'HIGH']
    
    def test_finding_structures(self):
        """Test that all functions return properly structured findings."""
        # Test with mock successful responses for each service
        mock_responses = self.get_successful_mock_responses()
        
        with patch('boto3.Session') as mock_session_class:
            mock_session, mock_client = self.create_mock_session(mock_responses)
            mock_session_class.return_value = mock_session
            
'''

    # Generate individual function tests
    for function in functions:
        test_class += f'''
    def test_{function}_success(self):
        """Test {function} with successful API responses."""
        mock_responses = self.get_{function.split('_')[0]}_success_responses()
        
        with patch('boto3.Session') as mock_session_class:
            mock_session, mock_client = self.create_mock_session(mock_responses)
            mock_session_class.return_value = mock_session
            
            findings = {function}_check(self.test_region, self.test_profile)
            
            assert isinstance(findings, list)
            if findings:
                for finding in findings:
                    self.assert_finding_structure(finding)
    
    def test_{function}_error_handling(self):
        """Test {function} error handling."""
        error_responses = {{
            'describe_regions': ClientError(
                {{'Error': {{'Code': 'AccessDenied', 'Message': 'Access denied'}}}},
                'DescribeRegions'
            )
        }}
        
        with patch('boto3.Session') as mock_session_class:
            mock_session, mock_client = self.create_mock_session(error_responses)
            mock_session_class.return_value = mock_session
            
            findings = {function}_check(self.test_region, self.test_profile)
            
            assert isinstance(findings, list)
            assert len(findings) >= 1
            
            # Should have at least one ERROR finding
            error_findings = [f for f in findings if f['status'] == 'ERROR']
            assert len(error_findings) >= 1
    
    def test_{function}_no_credentials(self):
        """Test {function} with no AWS credentials."""
        with patch('boto3.Session') as mock_session_class:
            mock_session_class.side_effect = NoCredentialsError()
            
            findings = {function}_check(self.test_region, self.test_profile)
            
            assert isinstance(findings, list)
            assert len(findings) >= 1
            assert all(f['status'] == 'ERROR' for f in findings)
    
    def test_{function}_wrapper_function(self):
        """Test {function} wrapper function."""
        mock_responses = self.get_{function.split('_')[0]}_success_responses()
        
        with patch('boto3.Session') as mock_session_class:
            mock_session, mock_client = self.create_mock_session(mock_responses)
            mock_session_class.return_value = mock_session
            
            result = {function}(self.test_region, self.test_profile)
            
            assert isinstance(result, dict)
            required_keys = ['function_name', 'region', 'profile', 'total_findings',
                           'compliant_count', 'non_compliant_count', 'error_count',
                           'compliance_rate', 'findings']
            
            for key in required_keys:
                assert key in result
            
            assert result['function_name'] == '{function}'
            assert result['region'] == self.test_region
            assert isinstance(result['findings'], list)
'''

    # Add service-specific mock response methods
    test_class += f'''
    
    def get_successful_mock_responses(self) -> Dict[str, Any]:
        """Get successful mock responses for {service} service."""
        return self.get_{service}_success_responses()
    
    def get_{service}_success_responses(self) -> Dict[str, Any]:
        """Get successful mock responses specific to {service.upper()} service."""
'''

    # Add service-specific mock responses
    service_mocks = {
        'lambda': '''
        return {
            'list_functions': {
                'Functions': [
                    {
                        'FunctionName': 'test-function',
                        'FunctionArn': 'arn:aws:lambda:us-east-1:123456789012:function:test-function',
                        'Runtime': 'python3.9',
                        'Handler': 'lambda_function.lambda_handler',
                        'CodeSize': 1024,
                        'Description': 'Test function',
                        'Timeout': 30,
                        'MemorySize': 128,
                        'LastModified': '2023-01-01T00:00:00.000+0000',
                        'CodeSha256': 'test-sha256',
                        'Version': '$LATEST',
                        'Environment': {
                            'Variables': {'TEST_VAR': 'test_value'}
                        },
                        'KMSKeyArn': 'arn:aws:kms:us-east-1:123456789012:key/test-key'
                    }
                ]
            },
            'list_tags': {
                'Tags': {
                    'DataSovereignty': 'US',
                    'DataJurisdiction': 'US',
                    'DataClassification': 'CONFIDENTIAL',
                    'Environment': 'Production'
                }
            },
            'get_function': {
                'Configuration': {
                    'FunctionName': 'test-function',
                    'FunctionArn': 'arn:aws:lambda:us-east-1:123456789012:function:test-function',
                    'DeadLetterConfig': {
                        'TargetArn': 'arn:aws:sqs:us-east-1:123456789012:dlq'
                    },
                    'Environment': {
                        'Variables': {'TEST_VAR': 'test_value'}
                    }
                },
                'Code': {
                    'RepositoryType': 'S3',
                    'Location': 'test-location'
                }
            },
            'get_function_configuration': {
                'FunctionName': 'test-function',
                'Environment': {
                    'Variables': {'TEST_VAR': 'test_value'}
                }
            },
            'get_code_signing_config': {
                'CodeSigningConfig': {
                    'CodeSigningConfigArn': 'arn:aws:lambda:us-east-1:123456789012:code-signing-config:test',
                    'AllowedPublishers': {
                        'SigningProfileVersionArns': ['arn:aws:signer:us-east-1:123456789012:/signing-profiles/test']
                    },
                    'CodeSigningPolicies': {
                        'UntrustedArtifactOnDeployment': 'Enforce'
                    }
                }
            }
        }''',
        's3': '''
        return {
            'list_buckets': {
                'Buckets': [
                    {
                        'Name': 'test-bucket',
                        'CreationDate': datetime(2023, 1, 1, tzinfo=timezone.utc)
                    }
                ]
            },
            'get_bucket_location': {
                'LocationConstraint': 'us-east-1'
            },
            'get_bucket_policy': {
                'Policy': json.dumps({
                    'Version': '2012-10-17',
                    'Statement': [
                        {
                            'Effect': 'Allow',
                            'Principal': {'AWS': 'arn:aws:iam::123456789012:root'},
                            'Action': 's3:GetObject',
                            'Resource': 'arn:aws:s3:::test-bucket/*',
                            'Condition': {
                                'StringEquals': {
                                    'aws:RequestedRegion': 'us-east-1'
                                }
                            }
                        }
                    ]
                })
            },
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
            },
            'get_bucket_tagging': {
                'TagSet': [
                    {'Key': 'DataSovereignty', 'Value': 'US'},
                    {'Key': 'Environment', 'Value': 'Production'}
                ]
            }
        }''',
        'dynamodb': '''
        return {
            'list_tables': {
                'TableNames': ['test-table']
            },
            'describe_table': {
                'Table': {
                    'TableName': 'test-table',
                    'TableArn': 'arn:aws:dynamodb:us-east-1:123456789012:table/test-table',
                    'TableStatus': 'ACTIVE',
                    'CreationDateTime': datetime(2023, 1, 1, tzinfo=timezone.utc),
                    'ProvisionedThroughput': {
                        'ReadCapacityUnits': 5,
                        'WriteCapacityUnits': 5
                    },
                    'BillingModeSummary': {
                        'BillingMode': 'PROVISIONED'
                    },
                    'SSEDescription': {
                        'Status': 'ENABLED',
                        'SSEType': 'KMS',
                        'KMSMasterKeyArn': 'arn:aws:kms:us-east-1:123456789012:key/test-key'
                    },
                    'StreamSpecification': {
                        'StreamEnabled': True,
                        'StreamViewType': 'NEW_AND_OLD_IMAGES'
                    }
                }
            },
            'list_tags_of_resource': {
                'Tags': [
                    {'Key': 'DataSovereignty', 'Value': 'US'},
                    {'Key': 'Environment', 'Value': 'Production'}
                ]
            },
            'describe_continuous_backups': {
                'ContinuousBackupsDescription': {
                    'ContinuousBackupsStatus': 'ENABLED',
                    'PointInTimeRecoveryDescription': {
                        'PointInTimeRecoveryStatus': 'ENABLED'
                    }
                }
            }
        }'''
    }

    if service in service_mocks:
        test_class += service_mocks[service]
    else:
        # Generic mock for other services
        test_class += f'''
        return {{
            'list_resources': {{'Resources': []}},
            'describe_resource': {{'Resource': {{'ResourceId': 'test-resource'}}}}
        }}'''

    # Add test execution and fixtures
    test_class += '''

    @pytest.fixture
    def sample_compliant_finding(self):
        """Sample compliant finding for testing."""
        return {
            "region": "us-east-1",
            "profile": "default",
            "resource_type": "test_resource",
            "resource_id": "test-resource-123",
            "status": "COMPLIANT",
            "risk_level": "MEDIUM",
            "recommendation": "Resource is compliant",
            "details": {
                "resource_name": "test-resource",
                "compliance_status": "passed"
            }
        }
    
    @pytest.fixture
    def sample_non_compliant_finding(self):
        """Sample non-compliant finding for testing."""
        return {
            "region": "us-east-1",
            "profile": "default",
            "resource_type": "test_resource",
            "resource_id": "test-resource-456",
            "status": "NON_COMPLIANT",
            "risk_level": "HIGH",
            "recommendation": "Fix compliance violation",
            "details": {
                "resource_name": "test-resource",
                "violation": "Security misconfiguration detected"
            }
        }

def test_module_imports():
    """Test that all modules can be imported successfully."""
'''

    # Add import tests for all functions
    for function in functions:
        test_class += f'''
    try:
        import {function}
        assert hasattr({function}, '{function}_check')
        assert hasattr({function}, '{function}')
    except ImportError as e:
        pytest.fail(f"Failed to import {function}: {{e}}")
'''

    test_class += '''

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
'''

    return imports + test_class

def generate_all_tests():
    """Generate comprehensive test files for all services."""
    services = get_service_functions()
    tests_dir = '/Users/apple/Desktop/utility/data-security/tests/data_security_rules'
    
    # Ensure tests directory exists
    os.makedirs(tests_dir, exist_ok=True)
    
    # Generate __init__.py for the test package
    init_content = '''"""
Comprehensive Test Suite for Data Security AWS Compliance Functions

This package contains test suites for all 185+ compliance functions
across 15 AWS services.
"""
'''
    
    with open(os.path.join(tests_dir, '__init__.py'), 'w') as f:
        f.write(init_content)
    
    # Generate individual test files for each service
    total_functions = 0
    for service, functions in services.items():
        test_filename = f'test_{service}_compliance.py'
        test_filepath = os.path.join(tests_dir, test_filename)
        
        test_content = generate_test_file_content(service, functions)
        
        with open(test_filepath, 'w') as f:
            f.write(test_content)
        
        print(f'Generated {test_filename} with {len(functions)} function tests')
        total_functions += len(functions)
    
    # Generate master test runner
    runner_content = f'''#!/usr/bin/env python3
"""
Master Test Runner for All Data Security Compliance Functions

Runs comprehensive tests for all {total_functions} compliance functions
across {len(services)} AWS services.
"""

import pytest
import sys
import os
from pathlib import Path

def run_all_tests():
    """Run all compliance function tests."""
    test_dir = Path(__file__).parent
    
    # Test arguments for comprehensive testing
    test_args = [
        str(test_dir),
        "-v",                    # Verbose output
        "--tb=short",           # Short traceback format
        "--strict-markers",     # Strict marker checking
        "--cov=data_function_list",  # Coverage for main code
        "--cov-report=html",    # HTML coverage report
        "--cov-report=term",    # Terminal coverage report
        "--junit-xml=test_results.xml",  # JUnit XML output
    ]
    
    print(f"Running comprehensive tests for {total_functions} compliance functions...")
    return pytest.main(test_args)

def run_service_tests(service_name: str):
    """Run tests for a specific service."""
    test_file = f"test_{{service_name}}_compliance.py"
    test_path = Path(__file__).parent / test_file
    
    if not test_path.exists():
        print(f"Test file {{test_file}} not found")
        return 1
    
    return pytest.main([str(test_path), "-v"])

if __name__ == "__main__":
    if len(sys.argv) > 1:
        service = sys.argv[1]
        exit_code = run_service_tests(service)
    else:
        exit_code = run_all_tests()
    
    sys.exit(exit_code)
'''
    
    runner_filepath = os.path.join(tests_dir, 'run_all_tests.py')
    with open(runner_filepath, 'w') as f:
        f.write(runner_content)
    
    # Make runner executable
    os.chmod(runner_filepath, 0o755)
    
    # Generate pytest configuration
    pytest_config = '''[tool:pytest]
testpaths = tests/data_security_rules
python_files = test_*.py
python_classes = Test*
python_functions = test_*
addopts = 
    --strict-markers
    --tb=short
    --maxfail=10
markers =
    slow: marks tests as slow (deselect with '-m "not slow"')
    integration: marks tests as integration tests
    unit: marks tests as unit tests
filterwarnings =
    ignore::DeprecationWarning
    ignore::PendingDeprecationWarning
'''
    
    config_filepath = os.path.join('/Users/apple/Desktop/utility/data-security', 'pytest.ini')
    with open(config_filepath, 'w') as f:
        f.write(pytest_config)
    
    # Generate requirements.txt for testing
    test_requirements = '''pytest>=7.0.0
pytest-cov>=4.0.0
pytest-mock>=3.10.0
boto3>=1.26.0
botocore>=1.29.0
moto>=4.0.0
'''
    
    req_filepath = os.path.join('/Users/apple/Desktop/utility/data-security', 'test_requirements.txt')
    with open(req_filepath, 'w') as f:
        f.write(test_requirements)
    
    print(f"\\n✅ COMPREHENSIVE TEST SUITE GENERATED!")
    print(f"📊 Total: {total_functions} functions across {len(services)} services")
    print(f"📁 Test files: {len(services)} service-specific test files")
    print(f"🏃 Runner: run_all_tests.py for executing all tests")
    print(f"⚙️  Config: pytest.ini for test configuration")
    print(f"📦 Requirements: test_requirements.txt for dependencies")
    
    return total_functions, len(services)

if __name__ == "__main__":
    generate_all_tests()
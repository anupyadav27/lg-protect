"""
Test Utilities and Helpers for LG-Protect CSPM Platform
Centralized testing utilities, assertions, and helper functions
"""

import time
import json
import asyncio
import requests
from typing import Dict, Any, List, Optional, Union
from pathlib import Path
import boto3
from moto import mock_ec2, mock_s3, mock_iam, mock_lambda, mock_rds
from unittest.mock import Mock, patch, MagicMock
import pytest
import psycopg2
import redis
from dataclasses import dataclass

from tests.config import get_test_config

@dataclass
class APITestResponse:
    """API test response wrapper"""
    status_code: int
    json_data: Dict[str, Any]
    headers: Dict[str, str]
    response_time_ms: float

class TestUtilities:
    """Centralized test utilities for common testing operations"""
    
    def __init__(self):
        self.config = get_test_config()
    
    # Database utilities
    def get_test_db_connection(self):
        """Get test database connection"""
        return psycopg2.connect(self.config.database_config['url'])
    
    def get_test_redis_connection(self):
        """Get test Redis connection"""
        return redis.from_url(self.config.redis_config['url'])
    
    def reset_test_database(self):
        """Reset test database to clean state"""
        conn = self.get_test_db_connection()
        try:
            cursor = conn.cursor()
            # Truncate all tables (customize based on your schema)
            cursor.execute("""
                TRUNCATE TABLE 
                    audit_logs, 
                    compliance_results, 
                    inventory_resources, 
                    security_findings, 
                    users, 
                    user_sessions 
                CASCADE;
            """)
            conn.commit()
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            conn.close()
    
    def reset_test_redis(self):
        """Reset test Redis to clean state"""
        redis_conn = self.get_test_redis_connection()
        redis_conn.flushdb()
    
    # API testing utilities
    def make_api_request(self, 
                        service: str, 
                        endpoint: str, 
                        method: str = "GET", 
                        data: Optional[Dict] = None,
                        headers: Optional[Dict] = None,
                        timeout: int = 30) -> APITestResponse:
        """Make API request to service endpoint"""
        base_url = self.config.get_service_url(service)
        url = f"{base_url}{endpoint}"
        
        if headers is None:
            headers = {"Content-Type": "application/json"}
        
        start_time = time.time()
        
        try:
            if method.upper() == "GET":
                response = requests.get(url, headers=headers, timeout=timeout)
            elif method.upper() == "POST":
                response = requests.post(url, json=data, headers=headers, timeout=timeout)
            elif method.upper() == "PUT":
                response = requests.put(url, json=data, headers=headers, timeout=timeout)
            elif method.upper() == "DELETE":
                response = requests.delete(url, headers=headers, timeout=timeout)
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")
            
            response_time = (time.time() - start_time) * 1000
            
            try:
                json_data = response.json()
            except:
                json_data = {}
            
            return APITestResponse(
                status_code=response.status_code,
                json_data=json_data,
                headers=dict(response.headers),
                response_time_ms=response_time
            )
        
        except requests.exceptions.RequestException as e:
            raise Exception(f"API request failed: {str(e)}")
    
    def wait_for_service(self, service: str, timeout: int = 60) -> bool:
        """Wait for service to be available"""
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            try:
                response = self.make_api_request(service, "/health")
                if response.status_code == 200:
                    return True
            except:
                pass
            time.sleep(1)
        
        return False
    
    # Test data utilities
    def load_test_fixture(self, fixture_name: str) -> Dict[str, Any]:
        """Load test fixture data"""
        fixtures_path = Path(__file__).parent.parent.parent.parent / "tests" / "fixtures"
        fixture_file = fixtures_path / f"{fixture_name}.json"
        
        if not fixture_file.exists():
            raise FileNotFoundError(f"Test fixture not found: {fixture_file}")
        
        with open(fixture_file, 'r') as f:
            return json.load(f)
    
    def create_test_user(self, role: str = "user") -> Dict[str, Any]:
        """Create test user"""
        import uuid
        return {
            "id": str(uuid.uuid4()),
            "username": f"test_user_{int(time.time())}",
            "email": f"test_{int(time.time())}@example.com",
            "role": role,
            "created_at": time.time(),
            "is_active": True
        }
    
    def create_test_aws_resource(self, resource_type: str) -> Dict[str, Any]:
        """Create test AWS resource"""
        import uuid
        
        base_resource = {
            "id": str(uuid.uuid4()),
            "arn": f"arn:aws:{resource_type}:us-east-1:123456789012:resource/test-{uuid.uuid4()}",
            "region": "us-east-1",
            "account_id": "123456789012",
            "created_at": time.time(),
            "tags": {"Environment": "test", "Service": "lg-protect"}
        }
        
        if resource_type == "ec2":
            base_resource.update({
                "instance_id": f"i-{uuid.uuid4().hex[:17]}",
                "instance_type": "t2.micro",
                "state": "running",
                "security_groups": [{"GroupId": f"sg-{uuid.uuid4().hex[:17]}"}]
            })
        elif resource_type == "s3":
            base_resource.update({
                "bucket_name": f"test-bucket-{uuid.uuid4().hex[:8]}",
                "location": "us-east-1",
                "versioning": False,
                "encryption": None
            })
        elif resource_type == "rds":
            base_resource.update({
                "db_instance_identifier": f"test-db-{uuid.uuid4().hex[:8]}",
                "engine": "postgres",
                "engine_version": "13.7",
                "instance_class": "db.t3.micro",
                "allocated_storage": 20
            })
        
        return base_resource

class CSMPAssertions:
    """Custom assertions for CSMP-specific testing"""
    
    @staticmethod
    def assert_compliance_result(result: Dict[str, Any], expected_status: str):
        """Assert compliance check result"""
        assert "status" in result, "Compliance result must have status field"
        assert "violations" in result, "Compliance result must have violations field"
        assert "checked_at" in result, "Compliance result must have checked_at timestamp"
        assert result["status"] == expected_status, f"Expected status {expected_status}, got {result['status']}"
        
        if expected_status == "compliant":
            assert len(result["violations"]) == 0, f"Compliant result should have no violations, found {len(result['violations'])}"
        elif expected_status == "non_compliant":
            assert len(result["violations"]) > 0, "Non-compliant result should have violations"
    
    @staticmethod
    def assert_security_finding(finding: Dict[str, Any], min_severity: str = "LOW"):
        """Assert security finding structure and content"""
        required_fields = ["id", "title", "severity", "description", "resource_id", "created_at"]
        for field in required_fields:
            assert field in finding, f"Security finding must have {field} field"
        
        valid_severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        assert finding["severity"] in valid_severities, f"Invalid severity: {finding['severity']}"
        
        severity_order = {s: i for i, s in enumerate(valid_severities)}
        assert severity_order[finding["severity"]] <= severity_order[min_severity], \
            f"Finding severity {finding['severity']} is below minimum {min_severity}"
    
    @staticmethod
    def assert_inventory_resource(resource: Dict[str, Any], resource_type: str):
        """Assert inventory resource structure"""
        required_fields = ["id", "type", "arn", "region", "account_id", "discovered_at"]
        for field in required_fields:
            assert field in resource, f"Inventory resource must have {field} field"
        
        assert resource["type"] == resource_type, f"Expected resource type {resource_type}, got {resource['type']}"
        assert resource["arn"].startswith("arn:aws:"), "ARN must be valid AWS ARN format"
    
    @staticmethod
    def assert_api_response_structure(response: APITestResponse, expected_fields: List[str]):
        """Assert API response has expected structure"""
        assert response.status_code == 200, f"Expected status 200, got {response.status_code}"
        
        for field in expected_fields:
            assert field in response.json_data, f"Response must have {field} field"
    
    @staticmethod
    def assert_performance_metrics(response: APITestResponse, max_response_time_ms: int = 1000):
        """Assert API performance metrics"""
        assert response.response_time_ms <= max_response_time_ms, \
            f"Response time {response.response_time_ms}ms exceeds maximum {max_response_time_ms}ms"
    
    @staticmethod
    def assert_audit_log(log_entry: Dict[str, Any]):
        """Assert audit log entry structure"""
        required_fields = ["timestamp", "user_id", "action", "resource", "result"]
        for field in required_fields:
            assert field in log_entry, f"Audit log must have {field} field"
        
        valid_results = ["success", "failure", "error"]
        assert log_entry["result"] in valid_results, f"Invalid audit result: {log_entry['result']}"

class MockAWSServices:
    """Mock AWS services for testing"""
    
    def __init__(self):
        self.mocks = {}
    
    def start_ec2_mock(self):
        """Start EC2 mock"""
        self.mocks['ec2'] = mock_ec2()
        self.mocks['ec2'].start()
        
        # Create some test instances
        client = boto3.client('ec2', region_name='us-east-1')
        
        # Create test VPC and subnet
        vpc = client.create_vpc(CidrBlock='10.0.0.0/16')
        subnet = client.create_subnet(
            VpcId=vpc['Vpc']['VpcId'],
            CidrBlock='10.0.1.0/24'
        )
        
        # Create test security group
        sg = client.create_security_group(
            GroupName='test-sg',
            Description='Test security group',
            VpcId=vpc['Vpc']['VpcId']
        )
        
        # Launch test instances
        instances = client.run_instances(
            ImageId='ami-12345678',
            MinCount=2,
            MaxCount=2,
            InstanceType='t2.micro',
            SubnetId=subnet['Subnet']['SubnetId'],
            SecurityGroupIds=[sg['GroupId']]
        )
        
        return instances['Instances']
    
    def start_s3_mock(self):
        """Start S3 mock"""
        self.mocks['s3'] = mock_s3()
        self.mocks['s3'].start()
        
        # Create test buckets
        client = boto3.client('s3', region_name='us-east-1')
        
        test_buckets = ['test-bucket-1', 'test-bucket-2', 'test-bucket-encrypted']
        for bucket_name in test_buckets:
            client.create_bucket(Bucket=bucket_name)
            
            # Add some test objects
            client.put_object(
                Bucket=bucket_name,
                Key='test-file.txt',
                Body=b'Test content'
            )
        
        return test_buckets
    
    def start_iam_mock(self):
        """Start IAM mock"""
        self.mocks['iam'] = mock_iam()
        self.mocks['iam'].start()
        
        client = boto3.client('iam', region_name='us-east-1')
        
        # Create test users
        test_users = ['test-user-1', 'test-user-2', 'admin-user']
        for username in test_users:
            client.create_user(UserName=username)
            
            # Create access key
            client.create_access_key(UserName=username)
        
        # Create test roles
        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "ec2.amazonaws.com"},
                    "Action": "sts:AssumeRole"
                }
            ]
        }
        
        client.create_role(
            RoleName='test-role',
            AssumeRolePolicyDocument=json.dumps(trust_policy)
        )
        
        return test_users
    
    def start_lambda_mock(self):
        """Start Lambda mock"""
        self.mocks['lambda'] = mock_lambda()
        self.mocks['lambda'].start()
        
        client = boto3.client('lambda', region_name='us-east-1')
        
        # Create test function
        function_code = """
def lambda_handler(event, context):
    return {'statusCode': 200, 'body': 'Hello from test Lambda!'}
"""
        
        client.create_function(
            FunctionName='test-function',
            Runtime='python3.9',
            Role='arn:aws:iam::123456789012:role/test-role',
            Handler='index.lambda_handler',
            Code={'ZipFile': function_code.encode()},
            Description='Test Lambda function'
        )
        
        return ['test-function']
    
    def start_rds_mock(self):
        """Start RDS mock"""
        self.mocks['rds'] = mock_rds()
        self.mocks['rds'].start()
        
        client = boto3.client('rds', region_name='us-east-1')
        
        # Create test DB instance
        client.create_db_instance(
            DBInstanceIdentifier='test-db-instance',
            DBInstanceClass='db.t3.micro',
            Engine='postgres',
            EngineVersion='13.7',
            AllocatedStorage=20,
            MasterUsername='testuser',
            MasterUserPassword='testpassword123'
        )
        
        return ['test-db-instance']
    
    def start_all_mocks(self):
        """Start all AWS service mocks"""
        services_created = {}
        
        try:
            services_created['ec2'] = self.start_ec2_mock()
            services_created['s3'] = self.start_s3_mock()
            services_created['iam'] = self.start_iam_mock()
            services_created['lambda'] = self.start_lambda_mock()
            services_created['rds'] = self.start_rds_mock()
        except Exception as e:
            # Stop any started mocks if there's an error
            self.stop_all_mocks()
            raise e
        
        return services_created
    
    def stop_all_mocks(self):
        """Stop all running mocks"""
        for service, mock_obj in self.mocks.items():
            try:
                mock_obj.stop()
            except:
                pass
        self.mocks.clear()

class TestDataGenerator:
    """Generate test data for various scenarios"""
    
    @staticmethod
    def generate_compliance_scenario(framework: str, compliance_status: str) -> Dict[str, Any]:
        """Generate compliance test scenario"""
        scenarios = {
            "SOC2": {
                "compliant": {
                    "encryption_at_rest": True,
                    "encryption_in_transit": True,
                    "access_logging_enabled": True,
                    "multi_factor_auth": True,
                    "password_policy_enforced": True
                },
                "non_compliant": {
                    "encryption_at_rest": False,
                    "encryption_in_transit": False,
                    "access_logging_enabled": False,
                    "multi_factor_auth": False,
                    "password_policy_enforced": False
                }
            },
            "HIPAA": {
                "compliant": {
                    "phi_encryption": True,
                    "access_controls": True,
                    "audit_logging": True,
                    "data_backup": True,
                    "incident_response": True
                },
                "non_compliant": {
                    "phi_encryption": False,
                    "access_controls": False,
                    "audit_logging": False,
                    "data_backup": False,
                    "incident_response": False
                }
            }
        }
        
        base_scenario = scenarios.get(framework, {}).get(compliance_status, {})
        
        return {
            "framework": framework,
            "expected_status": compliance_status,
            "controls": base_scenario,
            "test_resources": TestDataGenerator.generate_test_resources_for_framework(framework)
        }
    
    @staticmethod
    def generate_test_resources_for_framework(framework: str) -> List[Dict[str, Any]]:
        """Generate test resources specific to compliance framework"""
        utils = TestUtilities()
        
        if framework == "SOC2":
            return [
                utils.create_test_aws_resource("s3"),
                utils.create_test_aws_resource("ec2"),
                utils.create_test_aws_resource("rds")
            ]
        elif framework == "HIPAA":
            return [
                utils.create_test_aws_resource("s3"),
                utils.create_test_aws_resource("rds")
            ]
        
        return []
    
    @staticmethod
    def generate_performance_test_data(load_level: str) -> Dict[str, Any]:
        """Generate performance test data"""
        load_configs = {
            "light": {"concurrent_users": 10, "duration_seconds": 30, "ramp_up_seconds": 5},
            "medium": {"concurrent_users": 50, "duration_seconds": 60, "ramp_up_seconds": 10},
            "heavy": {"concurrent_users": 100, "duration_seconds": 120, "ramp_up_seconds": 20}
        }
        
        return load_configs.get(load_level, load_configs["light"])

# Pytest fixtures for common test setup
@pytest.fixture
def test_utils():
    """Provide test utilities instance"""
    return TestUtilities()

@pytest.fixture
def mock_aws_services():
    """Provide mock AWS services"""
    mock_services = MockAWSServices()
    created_services = mock_services.start_all_mocks()
    
    yield mock_services, created_services
    
    mock_services.stop_all_mocks()

@pytest.fixture
def clean_test_environment(test_utils):
    """Provide clean test environment"""
    # Setup
    test_utils.reset_test_database()
    test_utils.reset_test_redis()
    
    yield test_utils
    
    # Cleanup
    test_utils.reset_test_database()
    test_utils.reset_test_redis()

@pytest.fixture
def api_client(test_utils):
    """Provide API client for testing"""
    return test_utils

@pytest.fixture
def compliance_test_data():
    """Provide compliance test data"""
    return {
        "soc2_compliant": TestDataGenerator.generate_compliance_scenario("SOC2", "compliant"),
        "soc2_non_compliant": TestDataGenerator.generate_compliance_scenario("SOC2", "non_compliant"),
        "hipaa_compliant": TestDataGenerator.generate_compliance_scenario("HIPAA", "compliant"),
        "hipaa_non_compliant": TestDataGenerator.generate_compliance_scenario("HIPAA", "non_compliant")
    }
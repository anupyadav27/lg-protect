# Centralized Testing Framework for LG-Protect CSPM Platform

## Overview

This directory contains the enterprise-grade centralized testing framework for the LG-Protect CSPM platform. All services use this unified testing infrastructure to provide comprehensive test coverage, automated test execution, and consistent testing standards across all microservices.

## Features

### Enterprise Testing Capabilities
- **Unit Testing**: Comprehensive unit test coverage for all components
- **Integration Testing**: Service-to-service integration testing
- **API Testing**: Automated API endpoint testing with validation
- **Performance Testing**: Load testing and performance benchmarking
- **Security Testing**: Security vulnerability and penetration testing
- **Compliance Testing**: Regulatory compliance validation testing
- **End-to-End Testing**: Full workflow testing across all services
- **Contract Testing**: API contract validation between services

### Test Organization
```
/tests/
├── unit/                  # Unit tests for individual components
│   ├── api-gateway/
│   ├── inventory-service/
│   ├── compliance-service/
│   ├── data-security-service/
│   ├── alert-engine/
│   └── shared/
├── integration/           # Integration tests between services
│   ├── api_workflows/
│   ├── event_bus/
│   ├── database/
│   └── external_apis/
├── e2e/                   # End-to-end testing
│   ├── user_workflows/
│   ├── compliance_flows/
│   └── security_flows/
├── performance/           # Performance and load testing
│   ├── api_load_tests/
│   ├── database_performance/
│   └── stress_tests/
├── security/              # Security testing
│   ├── vulnerability_scans/
│   ├── penetration_tests/
│   └── auth_tests/
├── compliance/            # Compliance validation testing
│   ├── soc2/
│   ├── hipaa/
│   ├── pci_dss/
│   └── gdpr/
├── contract/              # Contract testing
│   ├── api_contracts/
│   └── event_contracts/
├── fixtures/              # Test data and fixtures
│   ├── sample_data/
│   ├── mock_responses/
│   └── test_configs/
├── reports/               # Test reports and coverage
│   ├── coverage/
│   ├── performance/
│   └── security/
└── utils/                 # Testing utilities and helpers
    ├── test_helpers/
    ├── mock_services/
    └── data_generators/
```

### Key Features
- **Centralized Test Configuration**: Unified test settings and configurations
- **Shared Test Utilities**: Common testing helpers and mock services
- **Automated Test Discovery**: Automatic test detection and execution
- **Parallel Test Execution**: High-performance parallel test running
- **Comprehensive Reporting**: Detailed test reports with coverage metrics
- **CI/CD Integration**: Seamless integration with deployment pipelines
- **Test Data Management**: Centralized test data and fixture management

## Quick Start

### 1. Basic Test Execution

```python
from tests.framework.test_runner import TestRunner

# Initialize test runner
runner = TestRunner("my-service")

# Run unit tests
runner.run_unit_tests()

# Run integration tests  
runner.run_integration_tests()

# Run all tests
runner.run_all_tests()
```

### 2. Service-Specific Testing

```python
from tests.framework.service_tester import ServiceTester

# Test specific service
tester = ServiceTester("inventory-service")

# Run API tests
tester.test_api_endpoints()

# Run database tests
tester.test_database_operations()

# Run event handling tests
tester.test_event_processing()
```

### 3. End-to-End Testing

```python
from tests.framework.e2e_tester import E2ETester

# Initialize E2E testing
e2e = E2ETester()

# Test complete workflows
e2e.test_compliance_workflow()
e2e.test_security_scan_workflow()
e2e.test_inventory_discovery_workflow()
```

## Testing Framework Components

### Test Runner
- Automated test discovery and execution
- Parallel test execution for performance
- Comprehensive reporting and metrics
- Integration with CI/CD pipelines

### Mock Services
- Mock AWS services for testing
- Mock external APIs and dependencies
- Test database with sample data
- Event bus simulation

### Test Data Management
- Fixture generation and management
- Sample data for different scenarios
- Test configuration management
- Environment-specific test data

### Assertion Libraries
- Custom assertions for CSPM-specific testing
- Security-focused test assertions
- Compliance validation assertions
- Performance benchmark assertions

## Test Categories

### Unit Tests
Test individual components in isolation:
- Service functions and methods
- Database models and operations
- Utility functions and helpers
- Business logic components

### Integration Tests
Test service interactions:
- API endpoint integration
- Database connectivity
- Event bus communication
- External service integration

### Performance Tests
Validate system performance:
- API response times
- Database query performance
- Concurrent user handling
- Resource utilization

### Security Tests
Validate security measures:
- Authentication and authorization
- Input validation and sanitization
- SQL injection prevention
- Cross-site scripting (XSS) prevention

### Compliance Tests
Validate regulatory compliance:
- SOC2 compliance validation
- HIPAA requirement testing
- PCI-DSS compliance checks
- GDPR compliance validation

## Configuration

### Environment Variables
```bash
# Test environment settings
TEST_ENV=development
TEST_DATABASE_URL=postgresql://test_user:test_pass@localhost:5432/test_db
TEST_REDIS_URL=redis://localhost:6379/1

# Test execution settings
TEST_PARALLEL_WORKERS=4
TEST_TIMEOUT_SECONDS=300
TEST_RETRY_COUNT=3

# Coverage settings
TEST_COVERAGE_THRESHOLD=80
TEST_COVERAGE_REPORT_FORMAT=html

# Mock service settings
MOCK_AWS_SERVICES=true
MOCK_EXTERNAL_APIS=true
TEST_DATA_FIXTURES=comprehensive
```

### Test Configuration File
```python
# tests/config/test_config.py
TEST_CONFIG = {
    'databases': {
        'test_db': 'postgresql://test_user:test_pass@localhost:5432/test_db'
    },
    'services': {
        'inventory_service_url': 'http://localhost:3000',
        'compliance_service_url': 'http://localhost:3001',
        'api_gateway_url': 'http://localhost:8000'
    },
    'timeouts': {
        'api_timeout': 30,
        'database_timeout': 10,
        'integration_timeout': 60
    },
    'coverage': {
        'minimum_threshold': 80,
        'report_format': 'html',
        'include_branches': True
    }
}
```

## Best Practices

### 1. Test Naming Conventions
```python
# Unit tests
def test_inventory_service_should_return_valid_resources_when_given_valid_credentials():
    pass

# Integration tests  
def test_api_gateway_should_route_requests_to_inventory_service():
    pass

# E2E tests
def test_complete_compliance_scan_workflow_should_generate_reports():
    pass
```

### 2. Test Structure
```python
# Arrange, Act, Assert pattern
def test_compliance_check():
    # Arrange
    mock_resources = create_mock_aws_resources()
    compliance_service = ComplianceService()
    
    # Act
    result = compliance_service.check_compliance(mock_resources)
    
    # Assert
    assert result.status == "compliant"
    assert len(result.violations) == 0
```

### 3. Mock Usage
```python
from tests.utils.mocks import MockAWSService

@patch('boto3.client')
def test_inventory_collection(mock_boto_client):
    # Setup mock
    mock_service = MockAWSService('ec2')
    mock_boto_client.return_value = mock_service
    
    # Test execution
    inventory = InventoryService()
    resources = inventory.collect_ec2_instances()
    
    # Assertions
    assert len(resources) > 0
    assert all(r.type == 'EC2Instance' for r in resources)
```

### 4. Test Data Management
```python
from tests.fixtures.aws_resources import get_sample_ec2_instances

def test_security_scan():
    # Use predefined test data
    test_instances = get_sample_ec2_instances()
    security_service = SecurityService()
    
    scan_result = security_service.scan_instances(test_instances)
    
    assert scan_result.total_scanned == len(test_instances)
```

## Integration Examples

### Example: API Gateway Testing
```python
import pytest
from tests.framework.api_tester import APITester

class TestAPIGateway:
    @pytest.fixture
    def api_tester(self):
        return APITester("api-gateway", base_url="http://localhost:8000")
    
    def test_health_endpoint(self, api_tester):
        response = api_tester.get("/health")
        assert response.status_code == 200
        assert response.json()["status"] == "healthy"
    
    def test_inventory_proxy(self, api_tester):
        response = api_tester.get("/api/v1/inventory/service-mapping")
        assert response.status_code == 200
        assert "data" in response.json()
```

### Example: Service Integration Testing
```python
from tests.framework.integration_tester import IntegrationTester

class TestServiceIntegration:
    def test_inventory_to_compliance_integration(self):
        tester = IntegrationTester()
        
        # Test complete flow from inventory to compliance
        inventory_result = tester.trigger_inventory_scan()
        assert inventory_result.success
        
        compliance_result = tester.trigger_compliance_check()
        assert compliance_result.success
        assert compliance_result.inventory_data_received
```

### Example: Performance Testing
```python
from tests.framework.performance_tester import PerformanceTester

class TestPerformance:
    def test_api_response_times(self):
        perf_tester = PerformanceTester()
        
        # Test API performance under load
        results = perf_tester.load_test(
            endpoint="/api/v1/inventory/service-mapping",
            concurrent_users=50,
            duration_seconds=60
        )
        
        assert results.average_response_time < 1000  # < 1 second
        assert results.error_rate < 0.01  # < 1% errors
```

## Test Execution Commands

### Run All Tests
```bash
# Run complete test suite
python -m pytest tests/ -v

# Run with coverage
python -m pytest tests/ --cov=backend --cov-report=html

# Run parallel tests
python -m pytest tests/ -n 4
```

### Run Specific Test Categories
```bash
# Unit tests only
python -m pytest tests/unit/ -v

# Integration tests only
python -m pytest tests/integration/ -v

# E2E tests only
python -m pytest tests/e2e/ -v

# Performance tests only
python -m pytest tests/performance/ -v
```

### Run Service-Specific Tests
```bash
# Test specific service
python -m pytest tests/unit/inventory-service/ -v

# Test API endpoints
python -m pytest tests/integration/api_workflows/ -v

# Test security features
python -m pytest tests/security/ -v
```

### Generate Reports
```bash
# Generate coverage report
python -m pytest tests/ --cov=backend --cov-report=html --cov-report=term

# Generate performance report
python -m pytest tests/performance/ --html=reports/performance.html

# Generate security test report
python -m pytest tests/security/ --html=reports/security.html
```

## Continuous Integration Integration

### GitHub Actions Example
```yaml
name: Test Suite
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Set up Python
        uses: actions/setup-python@v2
        with:
          python-version: 3.11
      
      - name: Install dependencies
        run: |
          pip install -r requirements-test.txt
      
      - name: Run tests
        run: |
          python -m pytest tests/ --cov=backend --cov-report=xml
      
      - name: Upload coverage
        uses: codecov/codecov-action@v1
```

## Test Data and Fixtures

### Sample AWS Resources
```python
# tests/fixtures/aws_resources.py
def get_sample_ec2_instances():
    return [
        {
            "InstanceId": "i-1234567890abcdef0",
            "InstanceType": "t2.micro",
            "State": {"Name": "running"},
            "SecurityGroups": [{"GroupId": "sg-12345678"}]
        }
    ]

def get_sample_s3_buckets():
    return [
        {
            "Name": "test-bucket-1",
            "CreationDate": "2024-01-01T00:00:00Z"
        }
    ]
```

### Mock Services
```python
# tests/utils/mocks/aws_mock.py
class MockEC2Service:
    def describe_instances(self, **kwargs):
        return {
            "Reservations": [
                {
                    "Instances": get_sample_ec2_instances()
                }
            ]
        }
```

## Troubleshooting

### Common Issues

1. **Test Database Connection Errors**
   ```bash
   # Ensure test database is running
   docker run -d --name test-postgres -p 5432:5432 -e POSTGRES_DB=test_db postgres:15
   ```

2. **Mock Service Configuration**
   ```python
   # Verify mock services are properly configured
   from tests.utils.test_validator import validate_test_environment
   validate_test_environment()
   ```

3. **Test Data Issues**
   ```bash
   # Reset test data
   python -m tests.utils.reset_test_data
   ```

## Support

For questions or issues with the testing framework:
1. Check the troubleshooting section above
2. Review service-specific test examples
3. Ensure proper test environment configuration
4. Verify test data fixtures are available

The centralized testing framework provides comprehensive test coverage for the entire LG-Protect CSMP platform, ensuring quality, reliability, and compliance across all services.
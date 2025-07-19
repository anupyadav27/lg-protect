"""
Centralized Test Configuration for LG-Protect CSPM Platform
Enterprise-grade test configuration and settings management
"""

import os
from pathlib import Path
from typing import Dict, Any, List
from dataclasses import dataclass

# Base configuration
TEST_BASE_PATH = Path(__file__).parent.parent.parent.parent / "tests"
TEST_RESULTS_PATH = TEST_BASE_PATH / "reports"
TEST_FIXTURES_PATH = TEST_BASE_PATH / "fixtures"

# Test environment settings
TEST_ENV = os.getenv('TEST_ENV', 'development')
DEBUG_MODE = os.getenv('DEBUG_MODE', 'false').lower() == 'true'

# Database configuration for testing
TEST_DATABASE_CONFIG = {
    'host': os.getenv('TEST_DB_HOST', 'localhost'),
    'port': int(os.getenv('TEST_DB_PORT', '5432')),
    'database': os.getenv('TEST_DB_NAME', 'lg_protect_test'),
    'user': os.getenv('TEST_DB_USER', 'test_user'),
    'password': os.getenv('TEST_DB_PASSWORD', 'test_password'),
    'url': os.getenv('TEST_DATABASE_URL', 'postgresql://test_user:test_password@localhost:5432/lg_protect_test')
}

# Redis configuration for testing
TEST_REDIS_CONFIG = {
    'host': os.getenv('TEST_REDIS_HOST', 'localhost'),
    'port': int(os.getenv('TEST_REDIS_PORT', '6379')),
    'db': int(os.getenv('TEST_REDIS_DB', '1')),
    'url': os.getenv('TEST_REDIS_URL', 'redis://localhost:6379/1')
}

# Service URLs for testing
TEST_SERVICE_URLS = {
    'api_gateway': os.getenv('TEST_API_GATEWAY_URL', 'http://localhost:8000'),
    'inventory_service': os.getenv('TEST_INVENTORY_SERVICE_URL', 'http://localhost:3000'),
    'compliance_service': os.getenv('TEST_COMPLIANCE_SERVICE_URL', 'http://localhost:3001'),
    'data_security_service': os.getenv('TEST_DATA_SECURITY_SERVICE_URL', 'http://localhost:3002'),
    'alert_engine': os.getenv('TEST_ALERT_ENGINE_URL', 'http://localhost:3010'),
}

# Test execution settings
TEST_EXECUTION_CONFIG = {
    'parallel_workers': int(os.getenv('TEST_PARALLEL_WORKERS', '4')),
    'timeout_seconds': int(os.getenv('TEST_TIMEOUT_SECONDS', '300')),
    'retry_count': int(os.getenv('TEST_RETRY_COUNT', '3')),
    'retry_delay_seconds': int(os.getenv('TEST_RETRY_DELAY', '1')),
    'verbose_output': os.getenv('TEST_VERBOSE', 'true').lower() == 'true'
}

# Coverage configuration
TEST_COVERAGE_CONFIG = {
    'minimum_threshold': int(os.getenv('TEST_COVERAGE_THRESHOLD', '80')),
    'report_format': os.getenv('TEST_COVERAGE_REPORT_FORMAT', 'html'),
    'include_branches': os.getenv('TEST_COVERAGE_BRANCHES', 'true').lower() == 'true',
    'exclude_patterns': [
        '*/tests/*',
        '*/migrations/*',
        '*/venv/*',
        '*/virtualenv/*',
        '*/__pycache__/*'
    ]
}

# Mock service configuration
MOCK_SERVICES_CONFIG = {
    'enable_aws_mocks': os.getenv('MOCK_AWS_SERVICES', 'true').lower() == 'true',
    'enable_external_api_mocks': os.getenv('MOCK_EXTERNAL_APIS', 'true').lower() == 'true',
    'mock_data_fixtures': os.getenv('TEST_DATA_FIXTURES', 'comprehensive'),
    'aws_mock_regions': ['us-east-1', 'us-west-2', 'eu-west-1'],
    'aws_mock_account_id': '123456789012'
}

# Performance testing thresholds
PERFORMANCE_THRESHOLDS = {
    'api_response_time_ms': int(os.getenv('PERF_API_RESPONSE_TIME_MS', '1000')),
    'database_query_time_ms': int(os.getenv('PERF_DB_QUERY_TIME_MS', '500')),
    'max_error_rate_percent': float(os.getenv('PERF_MAX_ERROR_RATE', '1.0')),
    'max_memory_usage_mb': int(os.getenv('PERF_MAX_MEMORY_MB', '512')),
    'max_cpu_usage_percent': int(os.getenv('PERF_MAX_CPU_PERCENT', '80'))
}

# Security testing configuration
SECURITY_TEST_CONFIG = {
    'enable_vulnerability_scans': os.getenv('SECURITY_VULN_SCANS', 'true').lower() == 'true',
    'enable_penetration_tests': os.getenv('SECURITY_PEN_TESTS', 'false').lower() == 'true',
    'test_auth_bypass': os.getenv('SECURITY_TEST_AUTH_BYPASS', 'true').lower() == 'true',
    'test_sql_injection': os.getenv('SECURITY_TEST_SQL_INJECTION', 'true').lower() == 'true',
    'test_xss_prevention': os.getenv('SECURITY_TEST_XSS', 'true').lower() == 'true',
    'scan_dependencies': os.getenv('SECURITY_SCAN_DEPS', 'true').lower() == 'true'
}

# Compliance testing frameworks
COMPLIANCE_FRAMEWORKS = {
    'SOC2': {
        'enabled': os.getenv('TEST_SOC2_COMPLIANCE', 'true').lower() == 'true',
        'control_categories': ['CC6.1', 'CC6.2', 'CC6.3', 'CC6.7', 'CC6.8'],
        'test_data_encryption': True,
        'test_access_controls': True,
        'test_audit_logging': True
    },
    'HIPAA': {
        'enabled': os.getenv('TEST_HIPAA_COMPLIANCE', 'true').lower() == 'true',
        'safeguards': ['administrative', 'physical', 'technical'],
        'test_phi_protection': True,
        'test_access_controls': True,
        'test_data_integrity': True
    },
    'PCI_DSS': {
        'enabled': os.getenv('TEST_PCI_COMPLIANCE', 'true').lower() == 'true',
        'requirements': ['1', '2', '3', '4', '6', '8', '10', '11'],
        'test_card_data_protection': True,
        'test_secure_transmission': True,
        'test_vulnerability_management': True
    },
    'GDPR': {
        'enabled': os.getenv('TEST_GDPR_COMPLIANCE', 'true').lower() == 'true',
        'principles': ['lawfulness', 'purpose_limitation', 'data_minimization'],
        'test_data_protection': True,
        'test_consent_management': True,
        'test_data_portability': True
    },
    'ISO27001': {
        'enabled': os.getenv('TEST_ISO27001_COMPLIANCE', 'true').lower() == 'true',
        'domains': ['information_security_policies', 'access_control', 'cryptography'],
        'test_isms_controls': True,
        'test_risk_management': True,
        'test_incident_response': True
    }
}

# Test data configuration
TEST_DATA_CONFIG = {
    'sample_aws_resources': {
        'ec2_instances': 10,
        's3_buckets': 5,
        'rds_instances': 3,
        'lambda_functions': 8,
        'iam_users': 15,
        'security_groups': 12
    },
    'sample_users': {
        'admin_users': 2,
        'regular_users': 10,
        'readonly_users': 5
    },
    'compliance_scenarios': {
        'compliant_resources': 70,
        'non_compliant_resources': 30,
        'mixed_scenarios': 20
    }
}

# Reporting configuration
TEST_REPORTING_CONFIG = {
    'generate_html_reports': True,
    'generate_json_reports': True,
    'generate_junit_xml': True,
    'include_screenshots': True,
    'include_performance_metrics': True,
    'include_security_findings': True,
    'retention_days': 30
}

@dataclass
class TestConfiguration:
    """Central test configuration class"""
    
    # Environment settings
    test_env: str = TEST_ENV
    debug_mode: bool = DEBUG_MODE
    
    # Database configuration
    database_config: Dict[str, Any] = None
    redis_config: Dict[str, Any] = None
    
    # Service URLs
    service_urls: Dict[str, str] = None
    
    # Execution settings
    execution_config: Dict[str, Any] = None
    coverage_config: Dict[str, Any] = None
    
    # Mock services
    mock_services_config: Dict[str, Any] = None
    
    # Performance thresholds
    performance_thresholds: Dict[str, Any] = None
    
    # Security testing
    security_test_config: Dict[str, Any] = None
    
    # Compliance frameworks
    compliance_frameworks: Dict[str, Any] = None
    
    # Test data
    test_data_config: Dict[str, Any] = None
    
    # Reporting
    reporting_config: Dict[str, Any] = None
    
    def __post_init__(self):
        """Initialize configuration with default values"""
        if self.database_config is None:
            self.database_config = TEST_DATABASE_CONFIG
        if self.redis_config is None:
            self.redis_config = TEST_REDIS_CONFIG
        if self.service_urls is None:
            self.service_urls = TEST_SERVICE_URLS
        if self.execution_config is None:
            self.execution_config = TEST_EXECUTION_CONFIG
        if self.coverage_config is None:
            self.coverage_config = TEST_COVERAGE_CONFIG
        if self.mock_services_config is None:
            self.mock_services_config = MOCK_SERVICES_CONFIG
        if self.performance_thresholds is None:
            self.performance_thresholds = PERFORMANCE_THRESHOLDS
        if self.security_test_config is None:
            self.security_test_config = SECURITY_TEST_CONFIG
        if self.compliance_frameworks is None:
            self.compliance_frameworks = COMPLIANCE_FRAMEWORKS
        if self.test_data_config is None:
            self.test_data_config = TEST_DATA_CONFIG
        if self.reporting_config is None:
            self.reporting_config = TEST_REPORTING_CONFIG
    
    def get_service_url(self, service_name: str) -> str:
        """Get URL for specific service"""
        return self.service_urls.get(service_name, '')
    
    def is_compliance_framework_enabled(self, framework: str) -> bool:
        """Check if compliance framework testing is enabled"""
        return self.compliance_frameworks.get(framework, {}).get('enabled', False)
    
    def get_performance_threshold(self, metric: str) -> Any:
        """Get performance threshold for specific metric"""
        return self.performance_thresholds.get(metric)
    
    def validate_configuration(self) -> List[str]:
        """Validate test configuration and return any issues"""
        issues = []
        
        # Check required environment variables
        required_vars = [
            'TEST_DATABASE_URL',
            'TEST_REDIS_URL'
        ]
        
        for var in required_vars:
            if not os.getenv(var):
                issues.append(f"Missing required environment variable: {var}")
        
        # Validate service URLs
        for service, url in self.service_urls.items():
            if not url:
                issues.append(f"Missing URL for service: {service}")
        
        # Validate thresholds
        if self.coverage_config['minimum_threshold'] < 0 or self.coverage_config['minimum_threshold'] > 100:
            issues.append("Coverage threshold must be between 0 and 100")
        
        return issues

# Global test configuration instance
TEST_CONFIG = TestConfiguration()

# Utility functions
def get_test_config() -> TestConfiguration:
    """Get the global test configuration instance"""
    return TEST_CONFIG

def get_database_url() -> str:
    """Get test database URL"""
    return TEST_CONFIG.database_config['url']

def get_redis_url() -> str:
    """Get test Redis URL"""
    return TEST_CONFIG.redis_config['url']

def get_service_url(service_name: str) -> str:
    """Get URL for specific service"""
    return TEST_CONFIG.get_service_url(service_name)

def is_mock_enabled(service_type: str) -> bool:
    """Check if mocking is enabled for service type"""
    mock_config = TEST_CONFIG.mock_services_config
    if service_type == 'aws':
        return mock_config.get('enable_aws_mocks', False)
    elif service_type == 'external_api':
        return mock_config.get('enable_external_api_mocks', False)
    return False

def get_compliance_frameworks() -> List[str]:
    """Get list of enabled compliance frameworks"""
    enabled_frameworks = []
    for framework, config in TEST_CONFIG.compliance_frameworks.items():
        if config.get('enabled', False):
            enabled_frameworks.append(framework)
    return enabled_frameworks

def setup_test_environment():
    """Setup test environment and validate configuration"""
    config = get_test_config()
    issues = config.validate_configuration()
    
    if issues:
        raise ValueError(f"Test configuration issues: {', '.join(issues)}")
    
    # Create necessary directories
    TEST_BASE_PATH.mkdir(parents=True, exist_ok=True)
    TEST_RESULTS_PATH.mkdir(parents=True, exist_ok=True)
    TEST_FIXTURES_PATH.mkdir(parents=True, exist_ok=True)
    
    return config
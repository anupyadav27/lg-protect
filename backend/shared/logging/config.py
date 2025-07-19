# Centralized Logging Configuration for LG-Protect CSPM Platform
# This file configures enterprise-grade logging for all services

import os
from pathlib import Path

# Base configuration
LOG_BASE_PATH = Path(__file__).parent.parent.parent / "logs"
LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
DEBUG_MODE = os.getenv('DEBUG_MODE', 'false').lower() == 'true'

# Log rotation settings
LOG_MAX_SIZE_MB = int(os.getenv('LOG_MAX_SIZE_MB', '50'))  # 50MB per file
LOG_BACKUP_COUNT = int(os.getenv('LOG_BACKUP_COUNT', '10'))  # Keep 10 backup files
LOG_MAX_SIZE_BYTES = LOG_MAX_SIZE_MB * 1024 * 1024

# Compliance and audit settings
ENABLE_AUDIT_LOGGING = os.getenv('ENABLE_AUDIT_LOGGING', 'true').lower() == 'true'
ENABLE_COMPLIANCE_LOGGING = os.getenv('ENABLE_COMPLIANCE_LOGGING', 'true').lower() == 'true'
ENABLE_SECURITY_LOGGING = os.getenv('ENABLE_SECURITY_LOGGING', 'true').lower() == 'true'
ENABLE_PERFORMANCE_LOGGING = os.getenv('ENABLE_PERFORMANCE_LOGGING', 'true').lower() == 'true'

# Sensitive data filtering
SENSITIVE_FIELDS = {
    'password', 'token', 'secret', 'key', 'authorization', 
    'auth', 'credential', 'private', 'confidential', 'ssn',
    'credit_card', 'cvv', 'social_security', 'api_key',
    'bearer', 'jwt', 'session_id', 'cookie'
}

# Log format templates
LOG_FORMATS = {
    'standard': '%(asctime)s | %(name)s | %(levelname)s | %(component)s | CID:%(correlation_id)s | %(message)s',
    'json': '%(message)s',
    'security': '%(asctime)s | %(name)s | SECURITY | SEVERITY:%(levelname)s | CID:%(correlation_id)s | %(message)s',
    'audit': '%(asctime)s | %(name)s | AUDIT | CID:%(correlation_id)s | %(message)s',
    'api': '%(asctime)s | %(name)s | API | %(method)s | %(endpoint)s | %(status_code)s | %(response_time)sms | CID:%(correlation_id)s | %(message)s',
    'compliance': '%(asctime)s | %(name)s | COMPLIANCE | FRAMEWORK:%(framework)s | CID:%(correlation_id)s | %(message)s'
}

# Service-specific log levels
SERVICE_LOG_LEVELS = {
    'api-gateway': 'INFO',
    'inventory-service': 'INFO',
    'compliance-service': 'INFO',
    'data-security-service': 'INFO',
    'alert-engine': 'INFO',
    'report-generator': 'INFO',
    'event-handler': 'DEBUG',
    'database': 'INFO',
    'auth': 'INFO'
}

# Enterprise compliance frameworks
COMPLIANCE_FRAMEWORKS = {
    'SOC2': {
        'enabled': True,
        'log_level': 'INFO',
        'retention_days': 2555  # 7 years
    },
    'HIPAA': {
        'enabled': True,
        'log_level': 'INFO',
        'retention_days': 2555  # 7 years
    },
    'PCI_DSS': {
        'enabled': True,
        'log_level': 'INFO',
        'retention_days': 365   # 1 year minimum
    },
    'ISO27001': {
        'enabled': True,
        'log_level': 'INFO',
        'retention_days': 1095  # 3 years
    },
    'GDPR': {
        'enabled': True,
        'log_level': 'INFO',
        'retention_days': 1095  # 3 years
    }
}

# Alert thresholds for log monitoring
ALERT_THRESHOLDS = {
    'error_rate_per_minute': 10,
    'critical_errors_per_hour': 5,
    'security_events_per_hour': 20,
    'failed_auth_attempts_per_minute': 5,
    'api_response_time_ms': 5000,
    'database_operation_time_ms': 2000
}

# Log aggregation settings
ENABLE_LOG_AGGREGATION = os.getenv('ENABLE_LOG_AGGREGATION', 'true').lower() == 'true'
LOG_AGGREGATION_INTERVAL_MINUTES = int(os.getenv('LOG_AGGREGATION_INTERVAL_MINUTES', '60'))

# External log shipping (for SIEM integration)
EXTERNAL_LOG_SHIPPING = {
    'enabled': os.getenv('EXTERNAL_LOG_SHIPPING_ENABLED', 'false').lower() == 'true',
    'endpoint': os.getenv('SIEM_ENDPOINT', ''),
    'api_key': os.getenv('SIEM_API_KEY', ''),
    'format': os.getenv('SIEM_LOG_FORMAT', 'json'),  # json, syslog, cef
    'batch_size': int(os.getenv('SIEM_BATCH_SIZE', '100')),
    'shipping_interval_seconds': int(os.getenv('SIEM_SHIPPING_INTERVAL', '300'))
}

# Log archival settings
LOG_ARCHIVAL = {
    'enabled': os.getenv('LOG_ARCHIVAL_ENABLED', 'true').lower() == 'true',
    'archive_after_days': int(os.getenv('LOG_ARCHIVE_AFTER_DAYS', '30')),
    'delete_after_days': int(os.getenv('LOG_DELETE_AFTER_DAYS', '2555')),  # 7 years default
    'compression': os.getenv('LOG_COMPRESSION', 'gzip'),
    'storage_path': os.getenv('LOG_ARCHIVE_PATH', str(LOG_BASE_PATH / 'archived'))
}

def get_service_log_level(service_name: str) -> str:
    """Get log level for specific service"""
    return SERVICE_LOG_LEVELS.get(service_name, LOG_LEVEL)

def is_compliance_enabled(framework: str) -> bool:
    """Check if compliance logging is enabled for a framework"""
    return COMPLIANCE_FRAMEWORKS.get(framework, {}).get('enabled', False)

def get_compliance_retention_days(framework: str) -> int:
    """Get retention days for compliance framework"""
    return COMPLIANCE_FRAMEWORKS.get(framework, {}).get('retention_days', 365)
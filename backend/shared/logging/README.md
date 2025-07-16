# Centralized Logging System for LG-Protect CSPM Platform

## Overview

This directory contains the enterprise-grade centralized logging system for the LG-Protect CSPM platform. All services use this unified logging infrastructure to provide comprehensive audit trails, performance monitoring, security event tracking, and compliance logging.

## Features

### Enterprise Logging Capabilities
- **Audit Logging**: Complete audit trails for all user and system actions
- **Security Event Logging**: Comprehensive security event tracking with severity levels
- **Compliance Logging**: Framework-specific compliance logging (SOC2, HIPAA, PCI-DSS, ISO27001, GDPR)
- **Performance Monitoring**: Automatic performance metrics collection
- **API Request/Response Logging**: Complete API interaction logging with correlation IDs
- **Database Operation Logging**: Detailed database operation tracking
- **Event Processing Logging**: Event bus and background task monitoring
- **Health Check Logging**: Service health and monitoring logs

### Log Organization
```
/logs/
├── services/              # Service-specific logs
│   ├── inventory-service/
│   ├── api-gateway/
│   ├── compliance-service/
│   └── ...
├── api/                   # API request/response logs
├── auth/                  # Authentication and authorization logs
├── audit/                 # Audit trail logs
├── compliance/            # Compliance framework logs
├── security/              # Security event logs
├── database/              # Database operation logs
├── events/                # Event processing logs
├── monitoring/            # Performance and health monitoring
│   ├── performance/
│   ├── health/
│   └── errors/
├── application/           # Application-wide logs
├── nginx/                 # Reverse proxy logs
└── archived/              # Archived logs
```

### Key Features
- **Log Rotation**: Automatic log rotation (50MB per file, 10 backups)
- **Correlation IDs**: Request tracking across services
- **Sensitive Data Filtering**: Automatic redaction of sensitive information
- **Structured Logging**: JSON and formatted logging support
- **Thread-Safe**: Singleton pattern with thread safety
- **Performance Decorators**: Automatic performance monitoring
- **Flask/FastAPI Middleware**: Easy integration with web frameworks

## Quick Start

### 1. Basic Usage

```python
from shared.logging.logger import get_logger

# Get logger instance
logger = get_logger("my-service", "my-component")

# Basic logging
logger.info("Service started successfully")
logger.warning("Configuration file not found, using defaults")
logger.error("Database connection failed", exception=e)

# Structured logging with extra data
logger.info("User action completed", extra_data={
    "user_id": "123",
    "action": "file_upload",
    "file_size": 1024
})
```

### 2. Flask Integration

```python
from flask import Flask
from shared.logging.middleware import setup_flask_logging

app = Flask(__name__)

# Setup centralized logging
setup_flask_logging(app, "my-service", "api")

@app.route("/api/data")
def get_data():
    # All requests automatically logged
    return {"data": "response"}
```

### 3. FastAPI Integration

```python
from fastapi import FastAPI
from shared.logging.middleware import setup_fastapi_logging

app = FastAPI()

# Setup centralized logging
setup_fastapi_logging(app, "my-service", "api")

@app.get("/api/data")
async def get_data():
    # All requests automatically logged
    return {"data": "response"}
```

## Specialized Logging

### Security Events
```python
logger.log_security_event(
    event_type="unauthorized_access_attempt",
    severity="high",
    user_id="user123",
    ip_address="192.168.1.100",
    details={
        "resource": "/admin/users",
        "method": "GET"
    }
)
```

### Audit Trail
```python
logger.log_audit_event(
    action="user_created",
    user_id="admin123",
    resource="user:new_user_id",
    result="success",
    details={
        "created_user_id": "new_user_id",
        "permissions": ["read", "write"]
    }
)
```

### Compliance Logging
```python
logger.log_compliance_event(
    compliance_framework="SOC2",
    rule_id="CC6.1",
    resource_id="database_server_1",
    status="compliant",
    details={
        "check_type": "encryption_at_rest",
        "result": "AES-256 encryption enabled"
    }
)
```

### Performance Monitoring
```python
# Manual performance logging
logger.log_performance(
    operation="database_query",
    duration_ms=150.5,
    extra_data={
        "query_type": "SELECT",
        "table": "users",
        "row_count": 100
    }
)

# Automatic performance monitoring with decorator
from shared.logging.middleware import log_performance

@log_performance(logger, "expensive_operation")
def expensive_function():
    # Function execution time automatically logged
    time.sleep(2)
    return "result"
```

### Database Operations
```python
from shared.logging.middleware import log_database_operation

@log_database_operation("SELECT", "users")
def get_users():
    # Database operation automatically logged
    return db.query("SELECT * FROM users")
```

### Authentication Events
```python
from shared.logging.middleware import log_auth_operation

@log_auth_operation("login")
def login_user(username, password):
    # Authentication attempt automatically logged
    return authenticate(username, password)
```

## Correlation IDs

Track requests across services using correlation IDs:

```python
from shared.logging.logger import CorrelationContext

# Manual correlation ID management
logger.set_correlation_id("custom-correlation-id")

# Context manager for automatic correlation ID handling
with CorrelationContext(logger, "request-123") as correlation_id:
    logger.info("Processing request")
    # All logs in this block will have the same correlation ID
```

## Configuration

### Environment Variables
```bash
# Log levels
LOG_LEVEL=INFO
DEBUG_MODE=false

# Log rotation
LOG_MAX_SIZE_MB=50
LOG_BACKUP_COUNT=10

# Features
ENABLE_AUDIT_LOGGING=true
ENABLE_COMPLIANCE_LOGGING=true
ENABLE_SECURITY_LOGGING=true
ENABLE_PERFORMANCE_LOGGING=true

# External integration
EXTERNAL_LOG_SHIPPING_ENABLED=false
SIEM_ENDPOINT=https://siem.company.com/api/logs
SIEM_API_KEY=your-api-key
SIEM_LOG_FORMAT=json

# Archival
LOG_ARCHIVAL_ENABLED=true
LOG_ARCHIVE_AFTER_DAYS=30
LOG_DELETE_AFTER_DAYS=2555  # 7 years
```

### Service-Specific Configuration
```python
from shared.logging.config import get_service_log_level

# Get log level for specific service
log_level = get_service_log_level("inventory-service")  # Returns "INFO"
```

## Compliance Frameworks

Supported compliance frameworks with automatic retention:

- **SOC2**: 7 years retention
- **HIPAA**: 7 years retention  
- **PCI-DSS**: 1 year retention
- **ISO27001**: 3 years retention
- **GDPR**: 3 years retention

```python
from shared.logging.config import is_compliance_enabled, get_compliance_retention_days

# Check if compliance logging is enabled
if is_compliance_enabled("SOC2"):
    logger.log_compliance_event(...)

# Get retention period
retention_days = get_compliance_retention_days("HIPAA")  # Returns 2555
```

## Log Formats

### Standard Format
```
2024-07-12 14:30:15 | inventory-service_main | INFO | main | CID:abc123 | Service started successfully
```

### JSON Format (for structured logs)
```json
{
  "timestamp": "2024-07-12T14:30:15.123Z",
  "service": "inventory-service",
  "component": "main",
  "level": "INFO",
  "correlation_id": "abc123",
  "message": "Service started successfully",
  "extra_data": {
    "user_id": "123",
    "action": "startup"
  }
}
```

### Security Event Format
```
2024-07-12 14:30:15 | api-gateway_security | SECURITY | SEVERITY:HIGH | CID:abc123 | Unauthorized access attempt detected
```

### API Request Format
```
2024-07-12 14:30:15 | api-gateway_api | API | POST | /api/users | 201 | 150ms | CID:abc123 | User creation request
```

## Best Practices

### 1. Use Appropriate Log Levels
- **DEBUG**: Detailed diagnostic information
- **INFO**: General information about system operation
- **WARNING**: Something unexpected happened, but system continues
- **ERROR**: Serious problem occurred
- **CRITICAL**: Very serious error occurred

### 2. Include Context
```python
# Good
logger.info("User login successful", extra_data={
    "user_id": user.id,
    "login_method": "oauth",
    "ip_address": request.remote_addr
})

# Avoid
logger.info("User logged in")
```

### 3. Use Correlation IDs
Always use correlation IDs for tracking requests across services.

### 4. Avoid Logging Sensitive Data
The system automatically filters sensitive data, but be mindful:
```python
# Automatically filtered
logger.info("Login attempt", extra_data={
    "username": "john@example.com",
    "password": "secret123"  # Will be redacted
})
```

### 5. Use Structured Logging
Prefer structured logging with extra_data over string formatting:
```python
# Good
logger.info("Database query completed", extra_data={
    "duration_ms": 150,
    "table": "users",
    "row_count": 100
})

# Avoid
logger.info(f"Database query on {table} took {duration}ms and returned {count} rows")
```

## Monitoring and Alerting

### Alert Thresholds
Default alert thresholds (configurable):
- Error rate: 10 errors/minute
- Critical errors: 5 errors/hour
- Security events: 20 events/hour
- Failed auth attempts: 5 attempts/minute
- API response time: >5000ms
- Database operation time: >2000ms

### Log Analysis Queries

#### High Error Rate Detection
```bash
grep "ERROR" logs/monitoring/errors/global_errors.log | tail -100
```

#### Security Events in Last Hour
```bash
grep "$(date -d '1 hour ago' '+%Y-%m-%d %H')" logs/security/security_events.log
```

#### Performance Issues
```bash
grep "slow_request.*true" logs/monitoring/performance/*.log
```

#### Compliance Violations
```bash
grep "non-compliant" logs/compliance/compliance_events.log
```

## Integration Examples

### Example: Inventory Service Integration
See `/backend/services/inventory-service/src/main.py` for complete integration example.

### Example: API Gateway Integration  
See `/backend/api-gateway/app.py` for complete integration example.

### Example: Custom Service Integration
```python
#!/usr/bin/env python3
"""
Custom Service with Centralized Logging
"""
from shared.logging.logger import get_logger, CorrelationContext
from shared.logging.middleware import (
    setup_fastapi_logging, 
    log_database_operation, 
    log_security_event
)

# Initialize logger
logger = get_logger("custom-service", "main")

# FastAPI app with logging
app = FastAPI()
setup_fastapi_logging(app, "custom-service", "api")

@app.on_event("startup")
async def startup():
    logger.info("Custom service starting up")
    logger.log_health_check("starting")

@log_database_operation("SELECT", "customers")
async def get_customers():
    # Database operation automatically logged
    return await db.fetch_all("SELECT * FROM customers")

@log_security_event("data_access", "medium")
async def access_sensitive_data():
    # Security event automatically logged
    return sensitive_data
```

## Troubleshooting

### Common Issues

1. **Permission Errors**
   ```bash
   # Ensure log directories have proper permissions
   chmod -R 755 /path/to/logs/
   ```

2. **Disk Space Issues**
   ```bash
   # Check log directory size
   du -sh /path/to/logs/
   
   # Manual log rotation if needed
   find /path/to/logs/ -name "*.log" -size +50M -exec logrotate {} \;
   ```

3. **Missing Correlation IDs**
   ```python
   # Always set correlation ID in request handlers
   logger.set_correlation_id(request.headers.get('X-Correlation-ID'))
   ```

## Log Retention and Archival

- **Active Logs**: Current and recent log files
- **Archived Logs**: Compressed logs moved to archive directory after 30 days
- **Retention**: Logs retained based on compliance requirements (up to 7 years)
- **Cleanup**: Automatic cleanup of expired logs

## Security Considerations

1. **Sensitive Data Filtering**: Automatic redaction of passwords, tokens, keys
2. **Access Control**: Restrict log file access to authorized personnel only
3. **Encryption**: Consider encrypting archived logs
4. **Audit Trail**: All log access should be audited
5. **SIEM Integration**: Forward logs to SIEM for security monitoring

## Support

For questions or issues with the logging system:
1. Check the troubleshooting section above
2. Review service-specific integration examples
3. Ensure proper environment configuration
4. Verify log directory permissions and disk space

The centralized logging system provides comprehensive observability for the entire LG-Protect CSPM platform, ensuring compliance, security, and operational excellence.
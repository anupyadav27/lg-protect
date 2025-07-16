import logging
import json
import os
from datetime import datetime
from pathlib import Path
import traceback
from typing import Optional, Dict, Any
import uuid
import time
from logging.handlers import RotatingFileHandler
import threading

class CSPMLogger:
    """
    Enhanced Centralized logging utility for CSPM platform
    All logs are organized in the main /logs folder with proper categorization
    Enterprise features: compliance logging, correlation IDs, log rotation, structured logging
    """
    
    _instances = {}
    _lock = threading.Lock()
    
    def __new__(cls, service_name: str, component: str = None):
        """Singleton pattern per service to avoid duplicate loggers"""
        key = f"{service_name}_{component or service_name}"
        if key not in cls._instances:
            with cls._lock:
                if key not in cls._instances:
                    cls._instances[key] = super(CSPMLogger, cls).__new__(cls)
        return cls._instances[key]
    
    def __init__(self, service_name: str, component: str = None):
        if hasattr(self, 'initialized'):
            return
        
        self.service_name = service_name
        self.component = component or service_name
        self.base_log_path = Path(__file__).parent.parent.parent.parent / "logs"
        self.correlation_id = None
        
        # Ensure log directories exist
        self._ensure_log_directories()
        
        # Setup loggers with rotation
        self.logger = self._setup_logger()
        self.error_logger = self._setup_error_logger()
        self.performance_logger = self._setup_performance_logger()
        self.security_logger = self._setup_security_logger()
        self.audit_logger = self._setup_audit_logger()
        self.database_logger = self._setup_database_logger()
        self.auth_logger = self._setup_auth_logger()
        self.event_logger = self._setup_event_logger()
        self.api_logger = self._setup_api_logger()
        self.compliance_logger = self._setup_compliance_logger()
        
        self.initialized = True
    
    def _ensure_log_directories(self):
        """Ensure all required log directories exist"""
        directories = [
            f"services/{self.service_name}",
            "events",
            "database",
            "auth",
            "monitoring/performance",
            "monitoring/health",
            "monitoring/errors",
            "application",
            "security",
            "audit",
            "api",
            "compliance",
            "nginx",
            "archived"
        ]
        
        for directory in directories:
            (self.base_log_path / directory).mkdir(parents=True, exist_ok=True)
    
    def _create_rotating_handler(self, log_path: Path, max_bytes: int = 50*1024*1024, backup_count: int = 10):
        """Create rotating file handler to prevent log files from growing too large"""
        return RotatingFileHandler(
            log_path,
            maxBytes=max_bytes,  # 50MB
            backupCount=backup_count
        )
    
    def _get_structured_formatter(self, log_type: str = "standard"):
        """Get structured formatter for consistent log format"""
        if log_type == "json":
            return logging.Formatter('%(message)s')
        elif log_type == "security":
            return logging.Formatter(
                '%(asctime)s | %(name)s | SECURITY | SEVERITY:%(levelname)s | CID:%(correlation_id)s | %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
        elif log_type == "audit":
            return logging.Formatter(
                '%(asctime)s | %(name)s | AUDIT | CID:%(correlation_id)s | %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
        elif log_type == "api":
            return logging.Formatter(
                '%(asctime)s | %(name)s | API | %(method)s | %(endpoint)s | %(status_code)s | %(response_time)sms | CID:%(correlation_id)s | %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
        else:
            return logging.Formatter(
                '%(asctime)s | %(name)s | %(levelname)s | %(component)s | CID:%(correlation_id)s | %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
    
    def set_correlation_id(self, correlation_id: str = None):
        """Set correlation ID for tracking requests across services"""
        self.correlation_id = correlation_id or str(uuid.uuid4())
        return self.correlation_id
    
    def get_correlation_id(self) -> str:
        """Get current correlation ID"""
        if not self.correlation_id:
            self.correlation_id = str(uuid.uuid4())
        return self.correlation_id
    
    def _setup_logger(self) -> logging.Logger:
        """Setup main application logger with rotation"""
        logger = logging.getLogger(f"{self.service_name}_main")
        logger.setLevel(logging.INFO)
        
        if not logger.handlers:
            # Rotating file handler for service-specific logs
            file_handler = self._create_rotating_handler(
                self.base_log_path / f"services/{self.service_name}/{self.service_name}.log"
            )
            
            # Application-wide handler with rotation
            app_handler = self._create_rotating_handler(
                self.base_log_path / "application/application.log"
            )
            
            # Console handler for development
            console_handler = logging.StreamHandler()
            
            # Formatter
            formatter = self._get_structured_formatter()
            
            for handler in [file_handler, app_handler, console_handler]:
                handler.setFormatter(formatter)
                logger.addHandler(handler)
        
        return logger
    
    def _setup_error_logger(self) -> logging.Logger:
        """Setup error-specific logger with rotation"""
        logger = logging.getLogger(f"{self.service_name}_errors")
        logger.setLevel(logging.ERROR)
        
        if not logger.handlers:
            # Error-specific file handler
            file_handler = self._create_rotating_handler(
                self.base_log_path / f"monitoring/errors/{self.service_name}_errors.log"
            )
            
            # Global errors handler
            global_handler = self._create_rotating_handler(
                self.base_log_path / "monitoring/errors/global_errors.log"
            )
            
            formatter = self._get_structured_formatter()
            
            for handler in [file_handler, global_handler]:
                handler.setFormatter(formatter)
                logger.addHandler(handler)
        
        return logger
    
    def _setup_performance_logger(self) -> logging.Logger:
        """Setup performance monitoring logger"""
        logger = logging.getLogger(f"{self.service_name}_performance")
        logger.setLevel(logging.INFO)
        
        if not logger.handlers:
            file_handler = self._create_rotating_handler(
                self.base_log_path / f"monitoring/performance/{self.service_name}_performance.log"
            )
            
            formatter = self._get_structured_formatter("json")
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
        
        return logger
    
    def _setup_security_logger(self) -> logging.Logger:
        """Setup security event logger"""
        logger = logging.getLogger(f"{self.service_name}_security")
        logger.setLevel(logging.INFO)
        
        if not logger.handlers:
            file_handler = self._create_rotating_handler(
                self.base_log_path / "security/security_events.log"
            )
            
            formatter = self._get_structured_formatter("security")
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
        
        return logger
    
    def _setup_audit_logger(self) -> logging.Logger:
        """Setup audit trail logger for compliance"""
        logger = logging.getLogger(f"{self.service_name}_audit")
        logger.setLevel(logging.INFO)
        
        if not logger.handlers:
            file_handler = self._create_rotating_handler(
                self.base_log_path / "audit/audit_trail.log"
            )
            
            formatter = self._get_structured_formatter("audit")
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
        
        return logger
    
    def _setup_database_logger(self) -> logging.Logger:
        """Setup database operation logger"""
        logger = logging.getLogger(f"{self.service_name}_database")
        logger.setLevel(logging.INFO)
        
        if not logger.handlers:
            file_handler = self._create_rotating_handler(
                self.base_log_path / "database/database_operations.log"
            )
            
            formatter = self._get_structured_formatter("json")
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
        
        return logger
    
    def _setup_auth_logger(self) -> logging.Logger:
        """Setup authentication logger"""
        logger = logging.getLogger(f"{self.service_name}_auth")
        logger.setLevel(logging.INFO)
        
        if not logger.handlers:
            file_handler = self._create_rotating_handler(
                self.base_log_path / "auth/auth_events.log"
            )
            
            formatter = self._get_structured_formatter("security")
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
        
        return logger
    
    def _setup_event_logger(self) -> logging.Logger:
        """Setup event system logger"""
        logger = logging.getLogger(f"{self.service_name}_events")
        logger.setLevel(logging.INFO)
        
        if not logger.handlers:
            file_handler = self._create_rotating_handler(
                self.base_log_path / "events/event_processing.log"
            )
            
            formatter = self._get_structured_formatter("json")
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
        
        return logger
    
    def _setup_api_logger(self) -> logging.Logger:
        """Setup API request/response logger"""
        logger = logging.getLogger(f"{self.service_name}_api")
        logger.setLevel(logging.INFO)
        
        if not logger.handlers:
            file_handler = self._create_rotating_handler(
                self.base_log_path / "api/api_requests.log"
            )
            
            formatter = self._get_structured_formatter("api")
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
        
        return logger
    
    def _setup_compliance_logger(self) -> logging.Logger:
        """Setup compliance logging for regulatory requirements"""
        logger = logging.getLogger(f"{self.service_name}_compliance")
        logger.setLevel(logging.INFO)
        
        if not logger.handlers:
            file_handler = self._create_rotating_handler(
                self.base_log_path / "compliance/compliance_events.log"
            )
            
            formatter = self._get_structured_formatter("audit")
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
        
        return logger
    
    # Main logging methods
    def info(self, message: str, extra_data: Dict[str, Any] = None):
        """Log info level message"""
        formatted_message = self._format_message(message, extra_data)
        self.logger.info(formatted_message, extra={
            'component': self.component,
            'correlation_id': self.get_correlation_id()
        })
    
    def warning(self, message: str, extra_data: Dict[str, Any] = None):
        """Log warning level message"""
        formatted_message = self._format_message(message, extra_data)
        self.logger.warning(formatted_message, extra={
            'component': self.component,
            'correlation_id': self.get_correlation_id()
        })
    
    def error(self, message: str, exception: Exception = None, extra_data: Dict[str, Any] = None):
        """Log error with optional exception details"""
        formatted_message = self._format_message(message, extra_data)
        
        if exception:
            formatted_message += f" | Exception: {str(exception)}"
            formatted_message += f" | Traceback: {traceback.format_exc()}"
        
        extra_info = {
            'component': self.component,
            'correlation_id': self.get_correlation_id()
        }
        
        self.logger.error(formatted_message, extra=extra_info)
        self.error_logger.error(formatted_message, extra=extra_info)
    
    def critical(self, message: str, exception: Exception = None, extra_data: Dict[str, Any] = None):
        """Log critical level message"""
        formatted_message = self._format_message(message, extra_data)
        
        if exception:
            formatted_message += f" | Exception: {str(exception)}"
            formatted_message += f" | Traceback: {traceback.format_exc()}"
        
        extra_info = {
            'component': self.component,
            'correlation_id': self.get_correlation_id()
        }
        
        self.logger.critical(formatted_message, extra=extra_info)
        self.error_logger.critical(formatted_message, extra=extra_info)
    
    def debug(self, message: str, extra_data: Dict[str, Any] = None):
        """Log debug level message"""
        formatted_message = self._format_message(message, extra_data)
        self.logger.debug(formatted_message, extra={
            'component': self.component,
            'correlation_id': self.get_correlation_id()
        })
    
    # API Request/Response Logging
    def log_api_request(self, method: str, endpoint: str, user_id: str = None, 
                       ip_address: str = None, user_agent: str = None,
                       request_body: Dict[str, Any] = None):
        """Log API request details"""
        api_data = {
            'type': 'request',
            'method': method,
            'endpoint': endpoint,
            'user_id': user_id,
            'ip_address': ip_address,
            'user_agent': user_agent,
            'service': self.service_name,
            'component': self.component,
            'timestamp': datetime.utcnow().isoformat(),
            'correlation_id': self.get_correlation_id()
        }
        
        # Only log non-sensitive request body data
        if request_body and not self._contains_sensitive_data(request_body):
            api_data['request_body'] = request_body
        
        message = json.dumps(api_data)
        self.api_logger.info(message, extra={
            'method': method,
            'endpoint': endpoint,
            'status_code': 'REQUEST',
            'response_time': 0,
            'correlation_id': self.get_correlation_id()
        })
    
    def log_api_response(self, method: str, endpoint: str, status_code: int, 
                        response_time_ms: float, user_id: str = None,
                        response_size: int = None, error_message: str = None):
        """Log API response details"""
        api_data = {
            'type': 'response',
            'method': method,
            'endpoint': endpoint,
            'status_code': status_code,
            'response_time_ms': response_time_ms,
            'user_id': user_id,
            'response_size': response_size,
            'service': self.service_name,
            'component': self.component,
            'timestamp': datetime.utcnow().isoformat(),
            'correlation_id': self.get_correlation_id()
        }
        
        if error_message:
            api_data['error_message'] = error_message
        
        message = json.dumps(api_data)
        self.api_logger.info(message, extra={
            'method': method,
            'endpoint': endpoint,
            'status_code': status_code,
            'response_time': response_time_ms,
            'correlation_id': self.get_correlation_id()
        })
    
    # Specialized logging methods (enhanced versions)
    def log_performance(self, operation: str, duration_ms: float, extra_data: Dict[str, Any] = None):
        """Log performance metrics"""
        perf_data = {
            'operation': operation,
            'duration_ms': duration_ms,
            'service': self.service_name,
            'component': self.component,
            'timestamp': datetime.utcnow().isoformat(),
            'correlation_id': self.get_correlation_id()
        }
        if extra_data:
            perf_data.update(extra_data)
        
        message = json.dumps(perf_data)
        self.performance_logger.info(message)
    
    def log_security_event(self, event_type: str, severity: str = "medium", user_id: str = None, 
                          ip_address: str = None, details: Dict[str, Any] = None):
        """Log security events with severity levels"""
        security_data = {
            'event_type': event_type,
            'severity': severity,
            'service': self.service_name,
            'component': self.component,
            'timestamp': datetime.utcnow().isoformat(),
            'user_id': user_id,
            'ip_address': ip_address,
            'correlation_id': self.get_correlation_id()
        }
        if details:
            security_data.update(details)
        
        message = json.dumps(security_data)
        
        # Log with appropriate level based on severity
        if severity.lower() == "critical":
            self.security_logger.critical(message, extra={'correlation_id': self.get_correlation_id()})
        elif severity.lower() == "high":
            self.security_logger.error(message, extra={'correlation_id': self.get_correlation_id()})
        elif severity.lower() == "medium":
            self.security_logger.warning(message, extra={'correlation_id': self.get_correlation_id()})
        else:
            self.security_logger.info(message, extra={'correlation_id': self.get_correlation_id()})
    
    def log_audit_event(self, action: str, user_id: str, resource: str, 
                       result: str, details: Dict[str, Any] = None):
        """Log audit trail events for compliance"""
        audit_data = {
            'action': action,
            'user_id': user_id,
            'resource': resource,
            'result': result,
            'service': self.service_name,
            'component': self.component,
            'timestamp': datetime.utcnow().isoformat(),
            'correlation_id': self.get_correlation_id()
        }
        if details:
            audit_data.update(details)
        
        message = json.dumps(audit_data)
        self.audit_logger.info(message, extra={'correlation_id': self.get_correlation_id()})
    
    def log_compliance_event(self, compliance_framework: str, rule_id: str, 
                           resource_id: str, status: str, details: Dict[str, Any] = None):
        """Log compliance check events for regulatory requirements"""
        compliance_data = {
            'compliance_framework': compliance_framework,  # e.g., "SOC2", "HIPAA", "PCI-DSS"
            'rule_id': rule_id,
            'resource_id': resource_id,
            'status': status,  # e.g., "compliant", "non-compliant", "exception"
            'service': self.service_name,
            'component': self.component,
            'timestamp': datetime.utcnow().isoformat(),
            'correlation_id': self.get_correlation_id()
        }
        if details:
            compliance_data.update(details)
        
        message = json.dumps(compliance_data)
        self.compliance_logger.info(message, extra={'correlation_id': self.get_correlation_id()})
    
    def log_database_operation(self, operation: str, table: str, duration_ms: float = None,
                              record_count: int = None, details: Dict[str, Any] = None):
        """Log database operations"""
        db_data = {
            'operation': operation,
            'table': table,
            'service': self.service_name,
            'component': self.component,
            'timestamp': datetime.utcnow().isoformat(),
            'correlation_id': self.get_correlation_id()
        }
        if duration_ms is not None:
            db_data['duration_ms'] = duration_ms
        if record_count is not None:
            db_data['record_count'] = record_count
        if details:
            db_data.update(details)
        
        message = json.dumps(db_data)
        self.database_logger.info(message)
    
    def log_auth_event(self, event_type: str, user_id: str = None, success: bool = True,
                      ip_address: str = None, details: Dict[str, Any] = None):
        """Log authentication events"""
        auth_data = {
            'event_type': event_type,
            'user_id': user_id,
            'success': success,
            'ip_address': ip_address,
            'service': self.service_name,
            'component': self.component,
            'timestamp': datetime.utcnow().isoformat(),
            'correlation_id': self.get_correlation_id()
        }
        if details:
            auth_data.update(details)
        
        message = json.dumps(auth_data)
        self.auth_logger.info(message, extra={'correlation_id': self.get_correlation_id()})
    
    def log_event_processing(self, event_type: str, event_id: str = None, 
                           processing_time_ms: float = None, status: str = "processed",
                           details: Dict[str, Any] = None):
        """Log event processing"""
        event_data = {
            'event_type': event_type,
            'event_id': event_id,
            'status': status,
            'service': self.service_name,
            'component': self.component,
            'timestamp': datetime.utcnow().isoformat(),
            'correlation_id': self.get_correlation_id()
        }
        if processing_time_ms is not None:
            event_data['processing_time_ms'] = processing_time_ms
        if details:
            event_data.update(details)
        
        message = json.dumps(event_data)
        self.event_logger.info(message)
    
    def log_health_check(self, status: str, checks: Dict[str, Any] = None):
        """Log health check results"""
        health_data = {
            'status': status,
            'service': self.service_name,
            'component': self.component,
            'timestamp': datetime.utcnow().isoformat(),
            'correlation_id': self.get_correlation_id()
        }
        if checks:
            health_data['checks'] = checks
        
        # Log to both service-specific and health monitoring logs
        message = json.dumps(health_data)
        self.info(f"Health check: {message}")
        
        # Also log to health monitoring
        health_logger = logging.getLogger(f"{self.service_name}_health")
        if not health_logger.handlers:
            health_handler = self._create_rotating_handler(
                self.base_log_path / f"monitoring/health/{self.service_name}_health.log"
            )
            health_formatter = self._get_structured_formatter("json")
            health_handler.setFormatter(health_formatter)
            health_logger.addHandler(health_handler)
        
        health_logger.info(message)
    
    def _contains_sensitive_data(self, data: Dict[str, Any]) -> bool:
        """Check if data contains sensitive information that shouldn't be logged"""
        sensitive_fields = {
            'password', 'token', 'secret', 'key', 'authorization', 
            'auth', 'credential', 'private', 'confidential', 'ssn',
            'credit_card', 'cvv', 'social_security', 'api_key'
        }
        
        def check_recursive(obj, path=""):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    key_lower = key.lower()
                    if any(sensitive in key_lower for sensitive in sensitive_fields):
                        return True
                    if check_recursive(value, f"{path}.{key}" if path else key):
                        return True
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    if check_recursive(item, f"{path}[{i}]" if path else f"[{i}]"):
                        return True
            return False
        
        return check_recursive(data)
    
    def _format_message(self, message: str, extra_data: Dict[str, Any] = None) -> str:
        """Format message with optional extra data"""
        if extra_data:
            # Filter out sensitive data before logging
            safe_data = {}
            for key, value in extra_data.items():
                if not any(sensitive in key.lower() for sensitive in ['password', 'token', 'secret', 'key']):
                    safe_data[key] = value
                else:
                    safe_data[key] = "[REDACTED]"
            return f"{message} | Extra: {json.dumps(safe_data)}"
        return message

# Context manager for correlation ID
class CorrelationContext:
    """Context manager for setting correlation ID across operations"""
    
    def __init__(self, logger: CSPMLogger, correlation_id: str = None):
        self.logger = logger
        self.correlation_id = correlation_id or str(uuid.uuid4())
        self.previous_id = None
    
    def __enter__(self):
        self.previous_id = self.logger.correlation_id
        self.logger.set_correlation_id(self.correlation_id)
        return self.correlation_id
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.logger.correlation_id = self.previous_id

# Performance monitoring decorator
def log_performance(logger: CSPMLogger, operation_name: str = None):
    """Decorator to automatically log performance metrics"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            start_time = time.time()
            operation = operation_name or f"{func.__module__}.{func.__name__}"
            
            try:
                result = func(*args, **kwargs)
                duration_ms = (time.time() - start_time) * 1000
                logger.log_performance(operation, duration_ms, {'status': 'success'})
                return result
            except Exception as e:
                duration_ms = (time.time() - start_time) * 1000
                logger.log_performance(operation, duration_ms, {'status': 'error', 'error': str(e)})
                logger.error(f"Performance monitored operation failed: {operation}", e)
                raise
        return wrapper
    return decorator

# Convenience functions
def get_logger(service_name: str, component: str = None) -> CSPMLogger:
    """Get a logger instance for a service/component"""
    return CSPMLogger(service_name, component)

def get_global_logger() -> CSPMLogger:
    """Get a global logger instance"""
    return CSPMLogger("global", "system")

# Log level configuration
def configure_log_levels(debug_mode: bool = False):
    """Configure logging levels across all loggers"""
    if debug_mode:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)
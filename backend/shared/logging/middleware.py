"""
Flask/FastAPI Middleware for Centralized Logging
Automatically logs API requests, responses, errors, and performance metrics
"""

import time
import uuid
from typing import Callable, Dict, Any, Optional
from functools import wraps
import json

try:
    from fastapi import FastAPI, Request, Response, HTTPException as FastAPIHTTPException
    from fastapi.middleware.base import BaseHTTPMiddleware
    from starlette.middleware.base import RequestResponseEndpoint
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False

try:
    from flask import Flask, request, g, jsonify
    from werkzeug.exceptions import HTTPException
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False

if not FASTAPI_AVAILABLE and not FLASK_AVAILABLE:
    print("Warning: Neither FastAPI nor Flask is available. Logging middleware will be limited.")

from .logger import get_logger, CSPMLogger, CorrelationContext

class FlaskLoggingMiddleware:
    """Flask middleware for centralized logging"""
    
    def __init__(self, app: Flask, service_name: str, component: str = None):
        self.app = app
        self.service_name = service_name
        self.component = component or service_name
        self.logger = get_logger(service_name, component)
        
        # Register middleware
        self._register_before_request()
        self._register_after_request()
        self._register_error_handlers()
    
    def _register_before_request(self):
        """Register before request handler"""
        @self.app.before_request
        def before_request():
            # Set correlation ID
            correlation_id = request.headers.get('X-Correlation-ID') or str(uuid.uuid4())
            g.correlation_id = correlation_id
            g.start_time = time.time()
            
            # Set correlation ID in logger
            self.logger.set_correlation_id(correlation_id)
            
            # Log API request
            self.logger.log_api_request(
                method=request.method,
                endpoint=request.endpoint or request.path,
                user_id=getattr(g, 'user_id', None),
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent'),
                request_body=self._get_safe_request_body()
            )
    
    def _register_after_request(self):
        """Register after request handler"""
        @self.app.after_request
        def after_request(response):
            # Calculate response time
            response_time_ms = (time.time() - g.start_time) * 1000
            
            # Log API response
            self.logger.log_api_response(
                method=request.method,
                endpoint=request.endpoint or request.path,
                status_code=response.status_code,
                response_time_ms=response_time_ms,
                user_id=getattr(g, 'user_id', None),
                response_size=len(response.get_data()) if response.get_data() else 0
            )
            
            # Add correlation ID to response headers
            response.headers['X-Correlation-ID'] = g.correlation_id
            
            # Log performance if slow
            if response_time_ms > 1000:  # Log slow requests (>1s)
                self.logger.log_performance(
                    operation=f"{request.method} {request.endpoint or request.path}",
                    duration_ms=response_time_ms,
                    extra_data={
                        'status_code': response.status_code,
                        'slow_request': True
                    }
                )
            
            return response
    
    def _register_error_handlers(self):
        """Register error handlers"""
        @self.app.errorhandler(Exception)
        def handle_exception(e):
            # Calculate response time
            response_time_ms = (time.time() - getattr(g, 'start_time', time.time())) * 1000
            
            if isinstance(e, HTTPException):
                status_code = e.code
                error_message = str(e)
            else:
                status_code = 500
                error_message = str(e)
                
                # Log the full error for 500s
                self.logger.error(
                    f"Unhandled exception in {request.method} {request.endpoint or request.path}",
                    exception=e,
                    extra_data={
                        'user_id': getattr(g, 'user_id', None),
                        'ip_address': request.remote_addr,
                        'user_agent': request.headers.get('User-Agent')
                    }
                )
            
            # Log API response with error
            self.logger.log_api_response(
                method=request.method,
                endpoint=request.endpoint or request.path,
                status_code=status_code,
                response_time_ms=response_time_ms,
                user_id=getattr(g, 'user_id', None),
                error_message=error_message
            )
            
            # Return appropriate JSON response
            if isinstance(e, HTTPException):
                return e
            else:
                return jsonify({
                    'error': 'Internal server error',
                    'correlation_id': getattr(g, 'correlation_id', 'unknown')
                }), 500
    
    def _get_safe_request_body(self) -> Optional[Dict[str, Any]]:
        """Get request body if it's safe to log"""
        try:
            if request.content_type and 'application/json' in request.content_type:
                data = request.get_json(silent=True)
                if data and not self.logger._contains_sensitive_data(data):
                    return data
        except Exception:
            pass
        return None

if FASTAPI_AVAILABLE:
    class FastAPILoggingMiddleware(BaseHTTPMiddleware):
        """FastAPI middleware for centralized logging"""
        
        def __init__(self, app: FastAPI, service_name: str, component: str = None):
            super().__init__(app)
            self.service_name = service_name
            self.component = component or service_name
            self.logger = get_logger(service_name, component)
        
        async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
            # Set correlation ID
            correlation_id = request.headers.get('x-correlation-id') or str(uuid.uuid4())
            start_time = time.time()
            
            # Set correlation ID in logger
            self.logger.set_correlation_id(correlation_id)
            
            # Get request body safely
            request_body = await self._get_safe_request_body(request)
            
            # Log API request
            self.logger.log_api_request(
                method=request.method,
                endpoint=str(request.url.path),
                user_id=getattr(request.state, 'user_id', None),
                ip_address=request.client.host if request.client else None,
                user_agent=request.headers.get('user-agent'),
                request_body=request_body
            )
            
            try:
                # Process request
                response = await call_next(request)
                
                # Calculate response time
                response_time_ms = (time.time() - start_time) * 1000
                
                # Log API response
                self.logger.log_api_response(
                    method=request.method,
                    endpoint=str(request.url.path),
                    status_code=response.status_code,
                    response_time_ms=response_time_ms,
                    user_id=getattr(request.state, 'user_id', None),
                    response_size=len(response.body) if hasattr(response, 'body') else 0
                )
                
                # Add correlation ID to response headers
                response.headers['x-correlation-id'] = correlation_id
                
                # Log performance if slow
                if response_time_ms > 1000:  # Log slow requests (>1s)
                    self.logger.log_performance(
                        operation=f"{request.method} {request.url.path}",
                        duration_ms=response_time_ms,
                        extra_data={
                            'status_code': response.status_code,
                            'slow_request': True
                        }
                    )
                
                return response
                
            except Exception as e:
                # Calculate response time
                response_time_ms = (time.time() - start_time) * 1000
                
                if isinstance(e, FastAPIHTTPException):
                    status_code = e.status_code
                    error_message = e.detail
                else:
                    status_code = 500
                    error_message = str(e)
                    
                    # Log the full error for 500s
                    self.logger.error(
                        f"Unhandled exception in {request.method} {request.url.path}",
                        exception=e,
                        extra_data={
                            'user_id': getattr(request.state, 'user_id', None),
                            'ip_address': request.client.host if request.client else None,
                            'user_agent': request.headers.get('user-agent')
                        }
                    )
                
                # Log API response with error
                self.logger.log_api_response(
                    method=request.method,
                    endpoint=str(request.url.path),
                    status_code=status_code,
                    response_time_ms=response_time_ms,
                    user_id=getattr(request.state, 'user_id', None),
                    error_message=error_message
                )
                
                raise
        
        async def _get_safe_request_body(self, request: Request) -> Optional[Dict[str, Any]]:
            """Get request body if it's safe to log"""
            try:
                content_type = request.headers.get('content-type', '')
                if 'application/json' in content_type:
                    body = await request.body()
                    if body:
                        data = json.loads(body)
                        if not self.logger._contains_sensitive_data(data):
                            return data
            except Exception:
                pass
            return None

# Authentication logging decorator
def log_auth_operation(operation_type: str):
    """Decorator for logging authentication operations"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            logger = get_logger('auth', 'authentication')
            start_time = time.time()
            
            try:
                result = func(*args, **kwargs)
                duration_ms = (time.time() - start_time) * 1000
                
                # Determine success based on result
                success = True
                user_id = None
                
                if isinstance(result, dict):
                    success = result.get('success', True)
                    user_id = result.get('user_id')
                elif hasattr(result, 'user_id'):
                    user_id = result.user_id
                
                logger.log_auth_event(
                    event_type=operation_type,
                    user_id=user_id,
                    success=success,
                    details={
                        'duration_ms': duration_ms,
                        'operation': func.__name__
                    }
                )
                
                return result
                
            except Exception as e:
                duration_ms = (time.time() - start_time) * 1000
                
                logger.log_auth_event(
                    event_type=operation_type,
                    success=False,
                    details={
                        'duration_ms': duration_ms,
                        'operation': func.__name__,
                        'error': str(e)
                    }
                )
                
                logger.error(f"Authentication operation failed: {operation_type}", e)
                raise
        
        return wrapper
    return decorator

# Database operation logging decorator
def log_database_operation(operation_type: str, table_name: str = None):
    """Decorator for logging database operations"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            logger = get_logger('database', 'db_operations')
            start_time = time.time()
            
            # Try to extract table name from arguments if not provided
            actual_table_name = table_name
            if not actual_table_name and args:
                for arg in args:
                    if hasattr(arg, '__tablename__'):
                        actual_table_name = arg.__tablename__
                        break
                    elif isinstance(arg, str) and not actual_table_name:
                        actual_table_name = arg
            
            try:
                result = func(*args, **kwargs)
                duration_ms = (time.time() - start_time) * 1000
                
                # Try to get record count from result
                record_count = None
                if hasattr(result, '__len__'):
                    try:
                        record_count = len(result)
                    except:
                        pass
                elif hasattr(result, 'rowcount'):
                    record_count = result.rowcount
                
                logger.log_database_operation(
                    operation=operation_type,
                    table=actual_table_name or 'unknown',
                    duration_ms=duration_ms,
                    record_count=record_count,
                    details={
                        'function': func.__name__,
                        'success': True
                    }
                )
                
                return result
                
            except Exception as e:
                duration_ms = (time.time() - start_time) * 1000
                
                logger.log_database_operation(
                    operation=operation_type,
                    table=actual_table_name or 'unknown',
                    duration_ms=duration_ms,
                    details={
                        'function': func.__name__,
                        'success': False,
                        'error': str(e)
                    }
                )
                
                logger.error(f"Database operation failed: {operation_type}", e)
                raise
        
        return wrapper
    return decorator

# Security event logging decorator
def log_security_event(event_type: str, severity: str = "medium"):
    """Decorator for logging security events"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            logger = get_logger('security', 'security_events')
            
            try:
                result = func(*args, **kwargs)
                
                # Extract user info if available
                user_id = None
                ip_address = None
                
                # Try to get user info from Flask request context
                try:
                    from flask import request, g
                    user_id = getattr(g, 'user_id', None)
                    ip_address = request.remote_addr
                except:
                    pass
                
                logger.log_security_event(
                    event_type=event_type,
                    severity=severity,
                    user_id=user_id,
                    ip_address=ip_address,
                    details={
                        'function': func.__name__,
                        'success': True
                    }
                )
                
                return result
                
            except Exception as e:
                logger.log_security_event(
                    event_type=f"{event_type}_failed",
                    severity="high",
                    details={
                        'function': func.__name__,
                        'error': str(e)
                    }
                )
                
                logger.error(f"Security operation failed: {event_type}", e)
                raise
        
        return wrapper
    return decorator

# Compliance logging decorator
def log_compliance_check(framework: str, rule_id: str):
    """Decorator for logging compliance checks"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            logger = get_logger('compliance', 'compliance_checker')
            
            try:
                result = func(*args, **kwargs)
                
                # Determine compliance status from result
                status = "compliant"
                resource_id = "unknown"
                
                if isinstance(result, dict):
                    status = result.get('status', 'compliant')
                    resource_id = result.get('resource_id', 'unknown')
                elif hasattr(result, 'status'):
                    status = result.status
                    resource_id = getattr(result, 'resource_id', 'unknown')
                
                logger.log_compliance_event(
                    compliance_framework=framework,
                    rule_id=rule_id,
                    resource_id=resource_id,
                    status=status,
                    details={
                        'function': func.__name__,
                        'check_result': result if isinstance(result, (dict, str, bool)) else str(result)
                    }
                )
                
                return result
                
            except Exception as e:
                logger.log_compliance_event(
                    compliance_framework=framework,
                    rule_id=rule_id,
                    resource_id="unknown",
                    status="error",
                    details={
                        'function': func.__name__,
                        'error': str(e)
                    }
                )
                
                logger.error(f"Compliance check failed: {framework}:{rule_id}", e)
                raise
        
        return wrapper
    return decorator

# Utility functions for easy integration
def setup_flask_logging(app: Flask, service_name: str, component: str = None):
    """Quick setup for Flask application logging"""
    middleware = FlaskLoggingMiddleware(app, service_name, component)
    return middleware

def setup_fastapi_logging(app: FastAPI, service_name: str, component: str = None):
    """Quick setup for FastAPI application logging"""
    if not FASTAPI_AVAILABLE:
        print("Warning: FastAPI logging middleware not available. Skipping middleware setup.")
        return None
    
    middleware = FastAPILoggingMiddleware(app, service_name, component)
    app.add_middleware(FastAPILoggingMiddleware, service_name=service_name, component=component)
    return middleware
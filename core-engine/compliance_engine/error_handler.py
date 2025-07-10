#!/usr/bin/env python3
"""
Error Handling and Analytics Module

Handles comprehensive error logging, categorization, and analytics for compliance checks.
Separated from compliance_utils for better maintainability.
"""

import logging
import threading
from typing import Dict, Any, List
from datetime import datetime, timezone
from collections import defaultdict, Counter
import botocore.exceptions


class EnhancedErrorLogger:
    """Advanced error logging with categorization and analytics"""
    
    def __init__(self, session_id: str):
        self.session_id = session_id
        self.errors = []
        self.error_categories = Counter()
        self.service_errors = defaultdict(Counter)
        self.region_errors = defaultdict(Counter)
        self.account_errors = defaultdict(Counter)
        self.temporal_errors = defaultdict(list)
        self.lock = threading.Lock()
    
    def log_error(self, account_id: str, region: str, service: str, function: str, 
                  error_type: str, error_message: str, compliance_check: str = None):
        """Log error with comprehensive metadata"""
        with self.lock:
            error_record = {
                'account_id': account_id,
                'region': region,
                'service': service,
                'function': function,
                'compliance_check': compliance_check,
                'error_type': error_type,
                'error_message': str(error_message),
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'session_id': self.session_id
            }
            
            self.errors.append(error_record)
            self.error_categories[error_type] += 1
            self.service_errors[service][error_type] += 1
            self.region_errors[region][error_type] += 1
            self.account_errors[account_id][error_type] += 1
            
            # Temporal tracking
            hour_key = datetime.now().strftime('%Y-%m-%d-%H')
            self.temporal_errors[hour_key].append(error_record)
    
    def categorize_error(self, error: Exception) -> str:
        """Advanced error categorization"""
        error_str = str(error).lower()
        
        if isinstance(error, botocore.exceptions.ClientError):
            error_code = error.response.get('Error', {}).get('Code', '')
            
            # Access/Permission errors
            if any(code in error_code for code in ['AccessDenied', 'UnauthorizedOperation', 'Forbidden', 'InvalidUserID.NotFound']):
                return 'access_denied'
            # Service enablement/subscription
            elif any(code in error_code for code in ['SubscriptionRequiredException', 'NotSubscribed', 'OptInRequired', 'ServiceNotEnabled']):
                return 'service_not_enabled'
            # Parameter validation
            elif any(code in error_code for code in ['ValidationException', 'InvalidParameterValue', 'MissingParameter', 'InvalidParameter']):
                return 'parameter_validation'
            # Service unavailable/throttling
            elif any(code in error_code for code in ['ServiceUnavailable', 'Throttling', 'RequestLimitExceeded', 'TooManyRequests']):
                return 'service_unavailable'
            # Resource not found
            elif any(code in error_code for code in ['ResourceNotFoundException', 'NoSuchEntity', 'NoSuchBucket', 'NoSuchKey']):
                return 'resource_not_found'
            # Unsupported operation
            elif any(code in error_code for code in ['InvalidAction', 'UnsupportedOperation', 'OperationNotPermitted']):
                return 'unsupported_operation'
            # Region not supported
            elif any(code in error_code for code in ['UnsupportedRegion', 'InvalidRegion']):
                return 'region_not_supported'
        
        # Connection errors
        elif isinstance(error, botocore.exceptions.EndpointConnectionError):
            return 'endpoint_connection_error'
        elif isinstance(error, botocore.exceptions.NoCredentialsError):
            return 'credentials_error'
        # Parameter validation from boto3
        elif 'parameter validation failed' in error_str:
            return 'parameter_validation'
        # Function not found
        elif 'not found on' in error_str and 'client' in error_str:
            return 'function_not_found'
        # Timeout
        elif any(term in error_str for term in ['timeout', 'timed out', 'read timeout']):
            return 'timeout'
        
        return 'unknown'


def handle_enhanced_client_error(error: botocore.exceptions.ClientError, region: str, 
                                profile: str, service: str = None, compliance_check: str = None) -> Dict[str, Any]:
    """
    Enhanced AWS client error handling with detailed categorization.
    
    Args:
        error (botocore.exceptions.ClientError): AWS client error
        region (str): AWS region where error occurred
        profile (str): AWS profile being used
        service (str): AWS service name
        compliance_check (str): Compliance check function name
        
    Returns:
        Dict[str, Any]: Enhanced error information
    """
    error_code = error.response.get('Error', {}).get('Code', 'Unknown')
    error_message = error.response.get('Error', {}).get('Message', str(error))
    
    # Enhanced error categorization
    error_logger = EnhancedErrorLogger("temp")
    error_category = error_logger.categorize_error(error)
    
    return {
        'region': region,
        'profile': profile,
        'service': service,
        'compliance_check': compliance_check,
        'error_code': error_code,
        'error_message': error_message,
        'error_category': error_category,
        'error_type': 'ClientError',
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'request_id': error.response.get('ResponseMetadata', {}).get('RequestId')
    }


def handle_client_error(error: botocore.exceptions.ClientError, region: str, profile: str) -> Dict[str, Any]:
    """
    Handle and format AWS client errors.
    (Maintained for backward compatibility)
    """
    return handle_enhanced_client_error(error, region, profile)


# Thread-safe global statistics
lock = threading.Lock()
global_stats = {
    "total_api_calls": 0,
    "successful_calls": 0,
    "failed_calls": 0,
    "accounts_processed": 0,
    "regions_processed": 0
}


def update_global_stats(successful: bool = True, api_call: bool = True):
    """Update thread-safe global statistics"""
    with lock:
        if api_call:
            global_stats["total_api_calls"] += 1
            if successful:
                global_stats["successful_calls"] += 1
            else:
                global_stats["failed_calls"] += 1
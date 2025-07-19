#!/usr/bin/env python3
"""
AWS Client Manager for LG-Protect Inventory System

Enterprise-grade AWS client management with:
- Credential management and rotation
- Regional client caching
- Connection pooling and reuse
- Error handling and retry logic
- Performance monitoring
"""

import boto3
import botocore.config
import botocore.exceptions
from typing import Dict, Optional, Any
from dataclasses import dataclass, field
import structlog
import threading
from datetime import datetime, timezone
import json

logger = structlog.get_logger(__name__)

@dataclass
class ClientConfig:
    """Configuration for AWS client creation"""
    max_attempts: int = 3
    retry_mode: str = 'adaptive'
    connect_timeout: int = 60
    read_timeout: int = 60
    max_pool_connections: int = 50
    region_name: str = 'us-east-1'
    
    # Advanced configuration
    use_ssl: bool = True
    verify_ssl: bool = True
    parameter_validation: bool = True
    tcp_keepalive: bool = True
    
    def to_boto3_config(self) -> botocore.config.Config:
        """Convert to boto3 Config object"""
        return botocore.config.Config(
            retries={
                'max_attempts': self.max_attempts,
                'mode': self.retry_mode
            },
            connect_timeout=self.connect_timeout,
            read_timeout=self.read_timeout,
            max_pool_connections=self.max_pool_connections,
            use_ssl=self.use_ssl,
            parameter_validation=self.parameter_validation,
            tcp_keepalive=self.tcp_keepalive
        )

class AWSClientManager:
    """
    Enterprise AWS Client Manager
    
    Provides efficient, cached AWS client management with:
    - Thread-safe client caching by service and region
    - Automatic credential handling
    - Connection pooling and reuse
    - Performance monitoring and metrics
    - Error handling and recovery
    """
    
    def __init__(self, client_config: Optional[ClientConfig] = None):
        self.client_config = client_config or ClientConfig()
        self._clients: Dict[str, Any] = {}
        self._client_lock = threading.RLock()
        self._session_cache: Dict[str, boto3.Session] = {}
        
        # Performance metrics
        self._client_creation_count = 0
        self._client_cache_hits = 0
        self._client_cache_misses = 0
        
        logger.info("aws_client_manager_initialized",
                   max_attempts=self.client_config.max_attempts,
                   retry_mode=self.client_config.retry_mode,
                   max_pool_connections=self.client_config.max_pool_connections)
    
    def get_client(self, service_name: str, region_name: str = None) -> Optional[Any]:
        """
        Get AWS client for specified service and region
        
        Args:
            service_name: AWS service name (e.g., 'ec2', 's3', 'iam')
            region_name: AWS region name (e.g., 'us-east-1')
        
        Returns:
            AWS client instance or None if creation fails
        """
        if region_name is None:
            region_name = self.client_config.region_name
        
        client_key = f"{service_name}:{region_name}"
        
        # Check cache first (with read lock)
        with self._client_lock:
            if client_key in self._clients:
                self._client_cache_hits += 1
                logger.debug("aws_client_cache_hit", 
                           service=service_name, 
                           region=region_name)
                return self._clients[client_key]
        
        # Create new client (with write lock)
        try:
            self._client_cache_misses += 1
            client = self._create_client(service_name, region_name)
            
            if client:
                with self._client_lock:
                    self._clients[client_key] = client
                    self._client_creation_count += 1
                
                logger.debug("aws_client_created",
                           service=service_name,
                           region=region_name,
                           total_clients=len(self._clients))
            
            return client
            
        except Exception as e:
            logger.error("aws_client_creation_failed",
                        service=service_name,
                        region=region_name,
                        error=str(e))
            return None
    
    def _create_client(self, service_name: str, region_name: str) -> Optional[Any]:
        """Create a new AWS client instance"""
        try:
            # Get or create session for this region
            session = self._get_session(region_name)
            
            # Create client with optimized configuration
            config = self.client_config.to_boto3_config()
            
            client = session.client(
                service_name,
                region_name=region_name,
                config=config
            )
            
            # Validate client by making a simple call
            if self._validate_client(client, service_name):
                return client
            else:
                return None
                
        except botocore.exceptions.NoCredentialsError:
            logger.error("aws_credentials_not_found",
                        service=service_name,
                        region=region_name)
            return None
        except botocore.exceptions.ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', 'Unknown')
            logger.error("aws_client_error",
                        service=service_name,
                        region=region_name,
                        error_code=error_code,
                        error_message=str(e))
            return None
        except Exception as e:
            logger.error("aws_client_creation_exception",
                        service=service_name,
                        region=region_name,
                        error=str(e))
            return None
    
    def _get_session(self, region_name: str) -> boto3.Session:
        """Get or create boto3 session for region"""
        if region_name not in self._session_cache:
            session = boto3.Session(region_name=region_name)
            self._session_cache[region_name] = session
            logger.debug("aws_session_created", region=region_name)
        
        return self._session_cache[region_name]
    
    def _validate_client(self, client: Any, service_name: str) -> bool:
        """Validate client by making a simple API call"""
        try:
            # Make a lightweight call based on service type
            validation_calls = {
                'ec2': lambda c: c.describe_regions(MaxResults=1),
                's3': lambda c: c.list_buckets(),
                'iam': lambda c: c.get_user() if hasattr(c, 'get_user') else c.list_roles(MaxItems=1),
                'rds': lambda c: c.describe_db_engine_versions(MaxRecords=1),
                'lambda': lambda c: c.list_functions(MaxItems=1),
                'cloudformation': lambda c: c.list_stacks(MaxResults=1),
                'kms': lambda c: c.list_keys(Limit=1),
                'sns': lambda c: c.list_topics(),
                'sqs': lambda c: c.list_queues(MaxResults=1),
                'dynamodb': lambda c: c.list_tables(Limit=1),
                'elasticache': lambda c: c.describe_cache_clusters(MaxRecords=1),
                'elb': lambda c: c.describe_load_balancers(PageSize=1),
                'elbv2': lambda c: c.describe_load_balancers(PageSize=1),
                'apigateway': lambda c: c.get_rest_apis(limit=1),
                'route53': lambda c: c.list_hosted_zones(MaxItems='1'),
                'cloudwatch': lambda c: c.list_metrics(MaxRecords=1),
                'logs': lambda c: c.describe_log_groups(limit=1),
                'config': lambda c: c.describe_configuration_recorders(),
                'cloudtrail': lambda c: c.describe_trails(MaxResults=1)
            }
            
            validation_call = validation_calls.get(service_name)
            if validation_call:
                validation_call(client)
            else:
                # For unknown services, try a generic approach
                if hasattr(client, 'list_'):
                    # Try to find a list_ method
                    list_methods = [method for method in dir(client) if method.startswith('list_')]
                    if list_methods:
                        getattr(client, list_methods[0])()
                elif hasattr(client, 'describe_'):
                    # Try to find a describe_ method
                    describe_methods = [method for method in dir(client) if method.startswith('describe_')]
                    if describe_methods:
                        getattr(client, describe_methods[0])()
            
            return True
            
        except botocore.exceptions.ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', 'Unknown')
            
            # Some errors are acceptable for validation
            acceptable_errors = {
                'AccessDenied', 'UnauthorizedOperation', 'InvalidUserID.NotFound',
                'NoSuchBucket', 'NoSuchHostedZone', 'ResourceNotFoundFault'
            }
            
            if error_code in acceptable_errors:
                logger.debug("aws_client_validation_access_limited",
                           service=service_name,
                           error_code=error_code)
                return True
            else:
                logger.warning("aws_client_validation_failed",
                             service=service_name,
                             error_code=error_code)
                return False
                
        except Exception as e:
            logger.warning("aws_client_validation_exception",
                         service=service_name,
                         error=str(e))
            return False
    
    def get_available_regions(self, service_name: str = 'ec2') -> list:
        """Get list of available regions for a service"""
        try:
            session = boto3.Session()
            return session.get_available_regions(service_name)
        except Exception as e:
            logger.error("aws_regions_discovery_failed",
                        service=service_name,
                        error=str(e))
            return ['us-east-1', 'us-west-2', 'eu-west-1']  # Fallback regions
    
    def clear_cache(self, service_name: str = None, region_name: str = None) -> None:
        """Clear client cache (optionally filtered by service/region)"""
        with self._client_lock:
            if service_name and region_name:
                # Clear specific client
                client_key = f"{service_name}:{region_name}"
                if client_key in self._clients:
                    del self._clients[client_key]
                    logger.debug("aws_client_cache_cleared",
                               service=service_name,
                               region=region_name)
            elif service_name:
                # Clear all clients for service
                keys_to_remove = [key for key in self._clients.keys() if key.startswith(f"{service_name}:")]
                for key in keys_to_remove:
                    del self._clients[key]
                logger.debug("aws_client_cache_cleared_service",
                           service=service_name,
                           cleared_count=len(keys_to_remove))
            elif region_name:
                # Clear all clients for region
                keys_to_remove = [key for key in self._clients.keys() if key.endswith(f":{region_name}")]
                for key in keys_to_remove:
                    del self._clients[key]
                logger.debug("aws_client_cache_cleared_region",
                           region=region_name,
                           cleared_count=len(keys_to_remove))
            else:
                # Clear all clients
                cleared_count = len(self._clients)
                self._clients.clear()
                logger.info("aws_client_cache_cleared_all",
                          cleared_count=cleared_count)
    
    def get_cache_statistics(self) -> Dict[str, Any]:
        """Get client cache statistics"""
        with self._client_lock:
            total_requests = self._client_cache_hits + self._client_cache_misses
            hit_rate = (self._client_cache_hits / total_requests * 100) if total_requests > 0 else 0.0
            
            return {
                'total_clients_cached': len(self._clients),
                'total_sessions_cached': len(self._session_cache),
                'clients_created': self._client_creation_count,
                'cache_hits': self._client_cache_hits,
                'cache_misses': self._client_cache_misses,
                'cache_hit_rate_percent': round(hit_rate, 2),
                'cached_services': list(set(key.split(':')[0] for key in self._clients.keys())),
                'cached_regions': list(set(key.split(':')[1] for key in self._clients.keys()))
            }
    
    def test_connectivity(self, service_name: str = 'sts', region_name: str = None) -> Dict[str, Any]:
        """Test AWS connectivity and credentials"""
        if region_name is None:
            region_name = self.client_config.region_name
        
        test_results = {
            'service': service_name,
            'region': region_name,
            'connectivity': False,
            'credentials': False,
            'permissions': False,
            'latency_ms': None,
            'account_id': None,
            'error': None
        }
        
        try:
            start_time = datetime.now(timezone.utc)
            
            # Test with STS service (most reliable for connectivity testing)
            sts_client = self.get_client('sts', region_name)
            if not sts_client:
                test_results['error'] = 'Failed to create STS client'
                return test_results
            
            # Test credentials and get account info
            identity = sts_client.get_caller_identity()
            
            end_time = datetime.now(timezone.utc)
            latency = (end_time - start_time).total_seconds() * 1000
            
            test_results.update({
                'connectivity': True,
                'credentials': True,
                'permissions': True,
                'latency_ms': round(latency, 2),
                'account_id': identity.get('Account'),
                'user_arn': identity.get('Arn'),
                'user_id': identity.get('UserId')
            })
            
            # Test the requested service if different from STS
            if service_name != 'sts':
                service_client = self.get_client(service_name, region_name)
                if service_client:
                    # Try to validate the service client
                    service_valid = self._validate_client(service_client, service_name)
                    test_results['service_accessible'] = service_valid
                else:
                    test_results['service_accessible'] = False
                    test_results['error'] = f'Failed to create {service_name} client'
            
        except botocore.exceptions.NoCredentialsError:
            test_results['error'] = 'No AWS credentials found'
        except botocore.exceptions.ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', 'Unknown')
            test_results['error'] = f'AWS API Error: {error_code}'
            if error_code not in ['AccessDenied', 'UnauthorizedOperation']:
                test_results['connectivity'] = True  # Connection works, just no permissions
        except Exception as e:
            test_results['error'] = str(e)
        
        return test_results
    
    def __del__(self):
        """Cleanup on destruction"""
        try:
            self.clear_cache()
        except Exception:
            pass  # Ignore cleanup errors


# Singleton instance for global use
_default_client_manager = None

def get_default_client_manager() -> AWSClientManager:
    """Get the default AWS client manager instance"""
    global _default_client_manager
    if _default_client_manager is None:
        _default_client_manager = AWSClientManager()
    return _default_client_manager
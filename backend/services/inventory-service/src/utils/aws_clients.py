#!/usr/bin/env python3
"""
AWS Client Management for LG-Protect Inventory System

Enterprise-grade AWS client management with connection pooling, rate limiting,
error handling, and cross-account support for comprehensive asset discovery.
"""

import boto3
import asyncio
import time
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass, field
from enum import Enum
from concurrent.futures import ThreadPoolExecutor
from botocore.exceptions import ClientError, BotoCoreError, NoCredentialsError
from botocore.config import Config
import structlog

logger = structlog.get_logger(__name__)

class AWSRegion(Enum):
    """AWS regions for inventory discovery"""
    US_EAST_1 = "us-east-1"
    US_EAST_2 = "us-east-2"
    US_WEST_1 = "us-west-1"
    US_WEST_2 = "us-west-2"
    EU_WEST_1 = "eu-west-1"
    EU_WEST_2 = "eu-west-2"
    EU_WEST_3 = "eu-west-3"
    EU_CENTRAL_1 = "eu-central-1"
    EU_NORTH_1 = "eu-north-1"
    AP_NORTHEAST_1 = "ap-northeast-1"
    AP_NORTHEAST_2 = "ap-northeast-2"
    AP_NORTHEAST_3 = "ap-northeast-3"
    AP_SOUTHEAST_1 = "ap-southeast-1"
    AP_SOUTHEAST_2 = "ap-southeast-2"
    AP_SOUTH_1 = "ap-south-1"
    CA_CENTRAL_1 = "ca-central-1"
    SA_EAST_1 = "sa-east-1"

@dataclass
class ClientPoolConfig:
    """Configuration for AWS client pooling"""
    max_pool_connections: int = 50
    retries: int = 3
    connect_timeout: int = 10
    read_timeout: int = 30
    max_attempts: int = 3
    
@dataclass
class RateLimitConfig:
    """Rate limiting configuration per service"""
    service_name: str
    requests_per_second: float = 10.0
    burst_limit: int = 20
    backoff_factor: float = 2.0
    max_backoff: float = 60.0

@dataclass
class ClientMetrics:
    """Metrics for AWS client operations"""
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    rate_limited_requests: int = 0
    average_response_time: float = 0.0
    last_request_time: Optional[float] = None
    
    def update_request(self, success: bool, response_time: float, rate_limited: bool = False):
        """Update metrics for a request"""
        self.total_requests += 1
        self.last_request_time = time.time()
        
        if success:
            self.successful_requests += 1
        else:
            self.failed_requests += 1
            
        if rate_limited:
            self.rate_limited_requests += 1
            
        # Update average response time
        if self.total_requests == 1:
            self.average_response_time = response_time
        else:
            self.average_response_time = (
                (self.average_response_time * (self.total_requests - 1) + response_time) 
                / self.total_requests
            )

class RateLimiter:
    """Token bucket rate limiter for AWS API calls"""
    
    def __init__(self, requests_per_second: float, burst_limit: int):
        self.requests_per_second = requests_per_second
        self.burst_limit = burst_limit
        self.tokens = burst_limit
        self.last_refill = time.time()
        self._lock = asyncio.Lock()
    
    async def acquire(self) -> bool:
        """Acquire a token for making a request"""
        async with self._lock:
            now = time.time()
            # Refill tokens based on elapsed time
            elapsed = now - self.last_refill
            self.tokens = min(
                self.burst_limit,
                self.tokens + elapsed * self.requests_per_second
            )
            self.last_refill = now
            
            if self.tokens >= 1:
                self.tokens -= 1
                return True
            else:
                # Calculate wait time
                wait_time = (1 - self.tokens) / self.requests_per_second
                logger.debug("rate_limit_wait", wait_time=wait_time)
                await asyncio.sleep(wait_time)
                self.tokens = 0
                return True

class AWSClientManager:
    """
    Enterprise AWS client manager with pooling, rate limiting, and monitoring
    
    Provides:
    - Connection pooling and reuse
    - Per-service rate limiting
    - Cross-account role assumption
    - Comprehensive error handling
    - Performance monitoring
    - Automatic retries with backoff
    """
    
    def __init__(self, 
                 pool_config: Optional[ClientPoolConfig] = None,
                 default_region: str = "us-east-1"):
        """
        Initialize AWS client manager
        
        Args:
            pool_config: Configuration for client pooling
            default_region: Default AWS region
        """
        self.pool_config = pool_config or ClientPoolConfig()
        self.default_region = default_region
        
        # Client pools per service/region/account
        self.client_pools: Dict[str, boto3.client] = {}
        
        # Rate limiters per service
        self.rate_limiters: Dict[str, RateLimiter] = {}
        
        # Metrics per service
        self.metrics: Dict[str, ClientMetrics] = {}
        
        # Thread pool for synchronous operations
        self.thread_pool = ThreadPoolExecutor(max_workers=20, thread_name_prefix="aws_client")
        
        # Default rate limit configurations
        self.default_rate_limits = {
            'ec2': RateLimitConfig('ec2', 20.0, 40),
            's3': RateLimitConfig('s3', 100.0, 200),
            'iam': RateLimitConfig('iam', 10.0, 20),
            'rds': RateLimitConfig('rds', 10.0, 20),
            'lambda': RateLimitConfig('lambda', 15.0, 30),
            'cloudformation': RateLimitConfig('cloudformation', 5.0, 10),
            'elbv2': RateLimitConfig('elbv2', 15.0, 30),
            'cloudfront': RateLimitConfig('cloudfront', 5.0, 10),
            'route53': RateLimitConfig('route53', 10.0, 20),
        }
        
        # Initialize rate limiters
        self._initialize_rate_limiters()
        
        logger.info("aws_client_manager_initialized", 
                   max_pool_connections=self.pool_config.max_pool_connections,
                   default_region=self.default_region)
    
    def _initialize_rate_limiters(self):
        """Initialize rate limiters for all services"""
        try:
            for service_name, rate_config in self.default_rate_limits.items():
                self.rate_limiters[service_name] = RateLimiter(
                    rate_config.requests_per_second,
                    rate_config.burst_limit
                )
                self.metrics[service_name] = ClientMetrics()
            
            logger.debug("rate_limiters_initialized", 
                        services=list(self.rate_limiters.keys()))
                        
        except Exception as e:
            logger.error("rate_limiter_initialization_failed", error=str(e))
            raise
    
    def _get_client_key(self, service_name: str, region: str, account_id: Optional[str] = None) -> str:
        """Generate unique key for client pooling"""
        return f"{service_name}:{region}:{account_id or 'default'}"
    
    def _create_boto3_config(self, service_name: str) -> Config:
        """Create optimized boto3 configuration"""
        try:
            rate_config = self.default_rate_limits.get(
                service_name, 
                RateLimitConfig(service_name)
            )
            
            config = Config(
                region_name=self.default_region,
                retries={
                    'max_attempts': self.pool_config.max_attempts,
                    'mode': 'adaptive'
                },
                max_pool_connections=self.pool_config.max_pool_connections,
                connect_timeout=self.pool_config.connect_timeout,
                read_timeout=self.pool_config.read_timeout,
                signature_version='v4',
                s3={'addressing_style': 'virtual'} if service_name == 's3' else {}
            )
            
            return config
            
        except Exception as e:
            logger.error("boto3_config_creation_failed", 
                        service_name=service_name, 
                        error=str(e))
            raise
    
    def get_client(self, service_name: str, region: Optional[str] = None, 
                   account_id: Optional[str] = None, role_arn: Optional[str] = None) -> boto3.client:
        """
        Get AWS client with pooling and optimization
        
        Args:
            service_name: AWS service name (e.g., 'ec2', 's3')
            region: AWS region
            account_id: Target account ID for cross-account access
            role_arn: Role ARN to assume for cross-account access
            
        Returns:
            boto3.client: Configured AWS client
        """
        try:
            region = region or self.default_region
            client_key = self._get_client_key(service_name, region, account_id)
            
            # Check if client already exists in pool
            if client_key in self.client_pools:
                logger.debug("client_pool_hit", 
                           service_name=service_name, 
                           region=region,
                           account_id=account_id)
                return self.client_pools[client_key]
            
            # Create new client
            client = self._create_new_client(service_name, region, role_arn)
            
            # Add to pool
            self.client_pools[client_key] = client
            
            # Initialize metrics if not exists
            if service_name not in self.metrics:
                self.metrics[service_name] = ClientMetrics()
            
            logger.debug("new_client_created", 
                       service_name=service_name, 
                       region=region,
                       account_id=account_id,
                       pool_size=len(self.client_pools))
            
            return client
            
        except Exception as e:
            logger.error("client_creation_failed", 
                        service_name=service_name,
                        region=region,
                        account_id=account_id,
                        error=str(e))
            raise
    
    def _create_new_client(self, service_name: str, region: str, 
                          role_arn: Optional[str] = None) -> boto3.client:
        """Create new AWS client with proper configuration"""
        try:
            config = self._create_boto3_config(service_name)
            config.region_name = region
            
            if role_arn:
                # Cross-account access via role assumption
                session = self._create_cross_account_session(role_arn, region)
                client = session.client(service_name, config=config)
            else:
                # Default credentials
                client = boto3.client(service_name, config=config)
            
            return client
            
        except Exception as e:
            logger.error("boto3_client_creation_failed", 
                        service_name=service_name,
                        region=region,
                        role_arn=role_arn,
                        error=str(e))
            raise
    
    def _create_cross_account_session(self, role_arn: str, region: str) -> boto3.Session:
        """Create boto3 session for cross-account access"""
        try:
            sts_client = boto3.client('sts', region_name=region)
            
            # Assume role
            response = sts_client.assume_role(
                RoleArn=role_arn,
                RoleSessionName=f"lg-protect-inventory-{int(time.time())}"
            )
            
            credentials = response['Credentials']
            
            # Create session with assumed role credentials
            session = boto3.Session(
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken'],
                region_name=region
            )
            
            logger.debug("cross_account_session_created", 
                       role_arn=role_arn, 
                       region=region)
            
            return session
            
        except Exception as e:
            logger.error("cross_account_session_failed", 
                        role_arn=role_arn,
                        region=region,
                        error=str(e))
            raise
    
    async def make_api_call(self, service_name: str, method_name: str, 
                           region: Optional[str] = None, account_id: Optional[str] = None,
                           role_arn: Optional[str] = None, **kwargs) -> Tuple[bool, Any]:
        """
        Make rate-limited API call with error handling and metrics
        
        Args:
            service_name: AWS service name
            method_name: API method to call
            region: AWS region
            account_id: Target account ID
            role_arn: Role ARN for cross-account access
            **kwargs: Arguments for the API call
            
        Returns:
            Tuple[bool, Any]: (success, response_or_error)
        """
        start_time = time.time()
        rate_limited = False
        
        try:
            # Apply rate limiting
            if service_name in self.rate_limiters:
                await self.rate_limiters[service_name].acquire()
                rate_limited = True
            
            # Get client
            client = self.get_client(service_name, region, account_id, role_arn)
            
            # Make API call in thread pool (boto3 is synchronous)
            loop = asyncio.get_event_loop()
            method = getattr(client, method_name)
            
            response = await loop.run_in_executor(
                self.thread_pool, 
                lambda: method(**kwargs)
            )
            
            # Update metrics
            response_time = time.time() - start_time
            if service_name in self.metrics:
                self.metrics[service_name].update_request(True, response_time, rate_limited)
            
            logger.debug("api_call_successful", 
                       service_name=service_name,
                       method_name=method_name,
                       region=region,
                       response_time=response_time)
            
            return True, response
            
        except ClientError as e:
            response_time = time.time() - start_time
            error_code = e.response.get('Error', {}).get('Code', 'Unknown')
            
            # Update metrics
            if service_name in self.metrics:
                self.metrics[service_name].update_request(False, response_time, rate_limited)
            
            # Handle specific error types
            if error_code in ['Throttling', 'ThrottlingException', 'RequestLimitExceeded']:
                logger.warning("api_call_throttled", 
                             service_name=service_name,
                             method_name=method_name,
                             error_code=error_code)
                # Apply exponential backoff
                await asyncio.sleep(min(2 ** self.metrics[service_name].rate_limited_requests, 60))
                
            else:
                logger.error("api_call_client_error", 
                           service_name=service_name,
                           method_name=method_name,
                           error_code=error_code,
                           error_message=str(e))
            
            return False, e
            
        except BotoCoreError as e:
            response_time = time.time() - start_time
            
            # Update metrics
            if service_name in self.metrics:
                self.metrics[service_name].update_request(False, response_time, rate_limited)
            
            logger.error("api_call_botocore_error", 
                       service_name=service_name,
                       method_name=method_name,
                       error=str(e))
            
            return False, e
            
        except Exception as e:
            response_time = time.time() - start_time
            
            # Update metrics
            if service_name in self.metrics:
                self.metrics[service_name].update_request(False, response_time, rate_limited)
            
            logger.error("api_call_unexpected_error", 
                       service_name=service_name,
                       method_name=method_name,
                       error=str(e))
            
            return False, e
    
    async def make_api_calls_batch(self, calls: List[Dict[str, Any]]) -> List[Tuple[bool, Any]]:
        """
        Make multiple API calls concurrently with rate limiting
        
        Args:
            calls: List of API call configurations
            
        Returns:
            List[Tuple[bool, Any]]: Results for each call
        """
        try:
            logger.info("batch_api_calls_started", call_count=len(calls))
            
            # Create tasks for all API calls
            tasks = []
            for call_config in calls:
                task = self.make_api_call(
                    service_name=call_config['service_name'],
                    method_name=call_config['method_name'],
                    region=call_config.get('region'),
                    account_id=call_config.get('account_id'),
                    role_arn=call_config.get('role_arn'),
                    **call_config.get('kwargs', {})
                )
                tasks.append(task)
            
            # Execute all calls concurrently
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Process results
            processed_results = []
            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    logger.error("batch_api_call_exception", 
                               call_index=i,
                               error=str(result))
                    processed_results.append((False, result))
                else:
                    processed_results.append(result)
            
            successful_calls = sum(1 for success, _ in processed_results if success)
            logger.info("batch_api_calls_completed", 
                       total_calls=len(calls),
                       successful_calls=successful_calls,
                       failed_calls=len(calls) - successful_calls)
            
            return processed_results
            
        except Exception as e:
            logger.error("batch_api_calls_failed", error=str(e))
            return [(False, e) for _ in calls]
    
    def get_metrics(self, service_name: Optional[str] = None) -> Dict[str, Any]:
        """Get client metrics for monitoring"""
        try:
            if service_name:
                if service_name in self.metrics:
                    return {
                        service_name: {
                            'total_requests': self.metrics[service_name].total_requests,
                            'successful_requests': self.metrics[service_name].successful_requests,
                            'failed_requests': self.metrics[service_name].failed_requests,
                            'rate_limited_requests': self.metrics[service_name].rate_limited_requests,
                            'average_response_time': self.metrics[service_name].average_response_time,
                            'success_rate': (
                                self.metrics[service_name].successful_requests / 
                                max(self.metrics[service_name].total_requests, 1) * 100
                            )
                        }
                    }
                else:
                    return {service_name: "No metrics available"}
            else:
                # Return all metrics
                all_metrics = {}
                for svc_name, metrics in self.metrics.items():
                    all_metrics[svc_name] = {
                        'total_requests': metrics.total_requests,
                        'successful_requests': metrics.successful_requests,
                        'failed_requests': metrics.failed_requests,
                        'rate_limited_requests': metrics.rate_limited_requests,
                        'average_response_time': metrics.average_response_time,
                        'success_rate': (
                            metrics.successful_requests / max(metrics.total_requests, 1) * 100
                        )
                    }
                
                # Add overall statistics
                total_requests = sum(m.total_requests for m in self.metrics.values())
                total_successful = sum(m.successful_requests for m in self.metrics.values())
                
                all_metrics['overall'] = {
                    'total_requests': total_requests,
                    'total_successful': total_successful,
                    'overall_success_rate': (total_successful / max(total_requests, 1) * 100),
                    'active_clients': len(self.client_pools),
                    'services_with_metrics': len(self.metrics)
                }
                
                return all_metrics
                
        except Exception as e:
            logger.error("metrics_retrieval_failed", error=str(e))
            return {"error": str(e)}
    
    async def test_connectivity(self, services: List[str], regions: List[str]) -> Dict[str, Dict[str, bool]]:
        """Test connectivity to AWS services across regions"""
        try:
            logger.info("testing_aws_connectivity", 
                       services=services, 
                       regions=regions)
            
            connectivity_results = {}
            
            for service_name in services:
                connectivity_results[service_name] = {}
                
                for region in regions:
                    try:
                        # Test basic service call
                        if service_name == 'ec2':
                            success, _ = await self.make_api_call(
                                service_name, 'describe_regions', region=region
                            )
                        elif service_name == 's3':
                            success, _ = await self.make_api_call(
                                service_name, 'list_buckets', region=region
                            )
                        elif service_name == 'iam':
                            success, _ = await self.make_api_call(
                                service_name, 'list_users', region=region, MaxItems=1
                            )
                        else:
                            # Generic test - try to get client
                            self.get_client(service_name, region)
                            success = True
                        
                        connectivity_results[service_name][region] = success
                        
                    except Exception as e:
                        logger.warning("connectivity_test_failed", 
                                     service_name=service_name,
                                     region=region,
                                     error=str(e))
                        connectivity_results[service_name][region] = False
            
            logger.info("connectivity_test_completed", results=connectivity_results)
            return connectivity_results
            
        except Exception as e:
            logger.error("connectivity_test_error", error=str(e))
            return {"error": str(e)}
    
    def cleanup(self):
        """Cleanup resources"""
        try:
            logger.info("cleaning_up_aws_client_manager")
            
            # Clear client pools
            self.client_pools.clear()
            
            # Shutdown thread pool
            self.thread_pool.shutdown(wait=True)
            
            logger.info("aws_client_manager_cleanup_completed")
            
        except Exception as e:
            logger.error("aws_client_manager_cleanup_failed", error=str(e))
    
    def __del__(self):
        """Destructor to ensure cleanup"""
        try:
            self.cleanup()
        except:
            pass  # Ignore errors during destruction
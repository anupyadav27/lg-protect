#!/usr/bin/env python3
"""
AWS Session Management Module

Handles AWS session creation, client configuration, and credential management.
Separated from compliance_utils for better maintainability.
"""

import boto3
import configparser
import os
import logging
from typing import Dict, List, Optional, Any
from botocore.config import Config

# Global Services Mapping
GLOBAL_SERVICES = {
    'iam': 'us-east-1',
    'organizations': 'us-east-1',
    'route53': 'us-east-1',
    's3': 'us-east-1',
    'cloudfront': 'us-east-1',
    'waf': 'us-east-1',
    'wafv2': 'us-east-1',
    'shield': 'us-east-1',
    'support': 'us-east-1',
    'budgets': 'us-east-1',
    'ce': 'us-east-1',
    'artifact': 'us-east-1',
    'account': 'us-east-1'
}

# Enhanced Configuration
DEFAULT_CONFIG = {
    'max_retries': 3,
    'timeout_seconds': 30,
    'connect_timeout': 15,
    'max_pool_connections': 100,
    'retry_mode': 'adaptive'
}


def get_aws_profiles() -> List[str]:
    """
    Get available AWS profiles from ~/.aws/config or return default.
    
    Returns:
        List[str]: List of available AWS profile names
    """
    try:
        aws_config_path = os.path.expanduser('~/.aws/config')
        if os.path.exists(aws_config_path):
            config = configparser.ConfigParser()
            config.read(aws_config_path)
            profiles = []
            for section in config.sections():
                if section.startswith('profile '):
                    profiles.append(section.replace('profile ', ''))
                elif section == 'default':
                    profiles.append('default')
            return profiles if profiles else ['default']
        else:
            logging.warning("AWS config file not found, using default profile")
            return ['default']
    except Exception as e:
        logging.error(f"Error reading AWS profiles: {e}")
        return ['default']


def create_aws_session(profile_name: Optional[str] = None) -> boto3.Session:
    """
    Create AWS session with specified profile.
    
    Args:
        profile_name (Optional[str]): AWS profile name
        
    Returns:
        boto3.Session: Configured AWS session
    """
    if profile_name == 'default' or profile_name is None:
        return boto3.Session()
    else:
        return boto3.Session(profile_name=profile_name)


def create_enhanced_aws_client(session: boto3.Session, service: str, region: str, 
                              config_override: Dict[str, Any] = None):
    """
    Create enhanced AWS service client with advanced configuration and proper region handling.
    
    Args:
        session (boto3.Session): AWS session
        service (str): AWS service name
        region (str): AWS region
        config_override (Dict[str, Any]): Override default configuration
        
    Returns:
        AWS service client with enhanced configuration
    """
    # Merge default config with overrides
    config_params = DEFAULT_CONFIG.copy()
    if config_override:
        config_params.update(config_override)
    
    # Handle global services
    if service in GLOBAL_SERVICES:
        region = GLOBAL_SERVICES[service]
    
    # Create enhanced configuration
    config = Config(
        retries={
            'max_attempts': config_params['max_retries'], 
            'mode': config_params['retry_mode']
        },
        read_timeout=config_params['timeout_seconds'],
        connect_timeout=config_params['connect_timeout'],
        max_pool_connections=config_params['max_pool_connections'],
        region_name=region
    )
    
    return session.client(service, config=config)


def create_aws_client(session: boto3.Session, service: str, region: str):
    """
    Create AWS service client with proper region handling for global services.
    (Maintained for backward compatibility)
    """
    return create_enhanced_aws_client(session, service, region)


def extract_service_name(api_function: str) -> str:
    """
    Extract AWS service name from API function string.
    
    Args:
        api_function (str): API function string containing service name
        
    Returns:
        str: Extracted service name or 'ec2' as default
    """
    try:
        # Handle multiple client declarations
        if "boto3.client('" in api_function:
            start = api_function.find("boto3.client('") + len("boto3.client('")
            end = api_function.find("')", start)
            if end > start:
                return api_function[start:end]
        elif 'boto3.client("' in api_function:
            start = api_function.find('boto3.client("') + len('boto3.client("')
            end = api_function.find('")', start)
            if end > start:
                return api_function[start:end]
    except Exception as e:
        logging.warning(f"Could not extract service from {api_function}: {e}")
    
    return 'ec2'  # Default fallback


def get_regions_for_service(service: str, service_regions: Dict[str, List[str]]) -> List[str]:
    """
    Get regions for a service based on global services mapping and configuration.
    
    Args:
        service (str): AWS service name
        service_regions (Dict[str, List[str]]): Service regions configuration
        
    Returns:
        List[str]: List of regions for the service
    """
    if service in GLOBAL_SERVICES:
        return [GLOBAL_SERVICES[service]]
    else:
        return service_regions.get(service, ['us-east-1', 'us-west-2'])
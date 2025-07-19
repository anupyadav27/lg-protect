#!/usr/bin/env python3
"""
Secret Manager

Handles AWS credentials and configuration for multiple clients.
Supports local files, AWS Secrets Manager, and HashiCorp Vault integration.
"""

import json
import os
import boto3
import logging
from pathlib import Path
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
from datetime import datetime

logger = logging.getLogger(__name__)

@dataclass
class AWSProfile:
    """AWS profile configuration"""
    name: str
    type: str  # 'shared_credentials', 'access_keys', 'role_assumption'
    region: str
    access_key_id: Optional[str] = None
    secret_access_key: Optional[str] = None
    role_arn: Optional[str] = None
    external_id: Optional[str] = None
    profile_name: Optional[str] = None
    account_id: Optional[str] = None
    account_name: Optional[str] = None

@dataclass
class ScanConfiguration:
    """Scan configuration"""
    default_regions: List[str]
    services_to_scan: List[str]
    max_workers: int
    scan_timeout_seconds: int

@dataclass
class OutputConfiguration:
    """Output configuration"""
    output_directory: str
    filename_prefix: str
    include_timestamp: bool
    format: str

class SecretProvider:
    """Secret management interface"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.secret_management_config = config.get('secret_management', {})
        self.secret_type = self.secret_management_config.get('type', 'local_file')
    
    def get_secrets(self) -> Dict[str, Any]:
        """Get secrets based on configured type"""
        if self.secret_type == 'local_file':
            return self._get_local_secrets()
        elif self.secret_type == 'aws_secrets_manager':
            return self._get_aws_secrets_manager_secrets()
        elif self.secret_type == 'hashicorp_vault':
            return self._get_hashicorp_vault_secrets()
        else:
            raise ValueError(f"Unsupported secret management type: {self.secret_type}")
    
    def _get_local_secrets(self) -> Dict[str, Any]:
        """Get secrets from local file"""
        secret_file_path = self.secret_management_config.get('secret_file_path', 'config/secrets.json')
        
        if not os.path.exists(secret_file_path):
            logger.warning(f"Secret file not found: {secret_file_path}")
            return {}
        
        try:
            with open(secret_file_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error reading secret file: {e}")
            return {}
    
    def _get_aws_secrets_manager_secrets(self) -> Dict[str, Any]:
        """Get secrets from AWS Secrets Manager"""
        try:
            secrets_config = self.secret_management_config.get('aws_secrets_manager', {})
            secret_name = secrets_config.get('secret_name', 'compliance-scan-credentials')
            region = secrets_config.get('region', 'us-east-1')
            
            # Create Secrets Manager client
            session = boto3.Session()
            secrets_client = session.client('secretsmanager', region_name=region)
            
            # Get secret
            response = secrets_client.get_secret_value(SecretId=secret_name)
            secret_string = response['SecretString']
            
            return json.loads(secret_string)
            
        except Exception as e:
            logger.error(f"Error getting secrets from AWS Secrets Manager: {e}")
            return {}
    
    def _get_hashicorp_vault_secrets(self) -> Dict[str, Any]:
        """Get secrets from HashiCorp Vault"""
        try:
            vault_config = self.secret_management_config.get('hashicorp_vault', {})
            vault_url = vault_config.get('vault_url')
            secret_path = vault_config.get('secret_path', 'aws/credentials')
            
            # This would integrate with hvac library for HashiCorp Vault
            # For now, return empty dict as placeholder
            logger.warning("HashiCorp Vault integration not implemented yet")
            return {}
            
        except Exception as e:
            logger.error(f"Error getting secrets from HashiCorp Vault: {e}")
            return {}

class SecretManager:
    """Main secret manager for AWS credentials and configuration"""
    
    def __init__(self, config_file: str = "config/aws_credentials_config.json"):
        self.config_file = config_file
        self.config = self._load_config()
        self.secret_provider = SecretProvider(self.config)
        self.secrets = self.secret_provider.get_secrets()
        
        # Parse configurations
        self.aws_profiles = self._parse_aws_profiles()
        self.scan_config = self._parse_scan_configuration()
        self.output_config = self._parse_output_configuration()
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from file"""
        if not os.path.exists(self.config_file):
            logger.warning(f"Config file not found: {self.config_file}")
            return {}
        
        try:
            with open(self.config_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error loading config file: {e}")
            return {}
    
    def _parse_aws_profiles(self) -> Dict[str, AWSProfile]:
        """Parse AWS profiles from configuration"""
        profiles = {}
        aws_config = self.config.get('aws_credentials', {})
        
        for profile_name, profile_config in aws_config.get('profiles', {}).items():
            # Get secrets for this profile
            profile_secrets = self.secrets.get('aws_credentials', {}).get(profile_name, {})
            
            profile = AWSProfile(
                name=profile_name,
                type=profile_config.get('type', 'shared_credentials'),
                region=profile_config.get('region', 'us-east-1'),
                access_key_id=profile_secrets.get('access_key_id') or profile_config.get('access_key_id'),
                secret_access_key=profile_secrets.get('secret_access_key') or profile_config.get('secret_access_key'),
                role_arn=profile_secrets.get('role_arn') or profile_config.get('role_arn'),
                external_id=profile_secrets.get('external_id') or profile_config.get('external_id'),
                profile_name=profile_config.get('profile_name'),
                account_id=profile_secrets.get('account_id'),
                account_name=profile_secrets.get('account_name')
            )
            profiles[profile_name] = profile
        
        return profiles
    
    def _parse_scan_configuration(self) -> ScanConfiguration:
        """Parse scan configuration"""
        scan_config = self.config.get('scan_configuration', {})
        
        return ScanConfiguration(
            default_regions=scan_config.get('default_regions', ['us-east-1']),
            services_to_scan=scan_config.get('services_to_scan', ['acm', 'account', 'accessanalyzer']),
            max_workers=scan_config.get('max_workers', 10),
            scan_timeout_seconds=scan_config.get('scan_timeout_seconds', 300)
        )
    
    def _parse_output_configuration(self) -> OutputConfiguration:
        """Parse output configuration"""
        output_config = self.config.get('output_configuration', {})
        
        return OutputConfiguration(
            output_directory=output_config.get('output_directory', 'output'),
            filename_prefix=output_config.get('filename_prefix', 'compliance_scan'),
            include_timestamp=output_config.get('include_timestamp', True),
            format=output_config.get('format', 'json')
        )
    
    def get_profile(self, profile_name: str) -> Optional[AWSProfile]:
        """Get AWS profile by name"""
        return self.aws_profiles.get(profile_name)
    
    def get_default_profile(self) -> Optional[AWSProfile]:
        """Get default AWS profile"""
        default_profile_name = self.config.get('aws_credentials', {}).get('default_profile', 'default')
        return self.get_profile(default_profile_name)
    
    def get_all_profiles(self) -> List[AWSProfile]:
        """Get all available profiles"""
        return list(self.aws_profiles.values())
    
    def create_boto3_session(self, profile_name: str) -> Optional[boto3.Session]:
        """Create boto3 session for a profile"""
        profile = self.get_profile(profile_name)
        if not profile:
            logger.error(f"Profile not found: {profile_name}")
            return None
        
        try:
            if profile.type == 'shared_credentials':
                return boto3.Session(profile_name=profile.profile_name, region_name=profile.region)
            
            elif profile.type == 'access_keys':
                return boto3.Session(
                    aws_access_key_id=profile.access_key_id,
                    aws_secret_access_key=profile.secret_access_key,
                    region_name=profile.region
                )
            
            elif profile.type == 'role_assumption':
                # First create session with base credentials
                base_session = boto3.Session(region_name=profile.region)
                sts_client = base_session.client('sts')
                
                # Assume role
                assume_role_kwargs = {
                    'RoleArn': profile.role_arn,
                    'RoleSessionName': f'compliance-scan-{datetime.now().strftime("%Y%m%d-%H%M%S")}'
                }
                
                if profile.external_id:
                    assume_role_kwargs['ExternalId'] = profile.external_id
                
                response = sts_client.assume_role(**assume_role_kwargs)
                
                # Create new session with assumed role credentials
                return boto3.Session(
                    aws_access_key_id=response['Credentials']['AccessKeyId'],
                    aws_secret_access_key=response['Credentials']['SecretAccessKey'],
                    aws_session_token=response['Credentials']['SessionToken'],
                    region_name=profile.region
                )
            
            else:
                logger.error(f"Unsupported profile type: {profile.type}")
                return None
                
        except Exception as e:
            logger.error(f"Error creating session for profile {profile_name}: {e}")
            return None
    
    def get_output_filename(self, profile_name: Optional[str] = None) -> str:
        """Generate output filename based on configuration"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        prefix = self.output_config.filename_prefix
        
        if profile_name:
            filename = f"{prefix}_{profile_name}_{timestamp}.json"
        else:
            filename = f"{prefix}_{timestamp}.json"
        
        return os.path.join(self.output_config.output_directory, filename)
    
    def validate_configuration(self) -> bool:
        """Validate configuration"""
        try:
            # Check if config file exists
            if not os.path.exists(self.config_file):
                logger.error(f"Config file not found: {self.config_file}")
                return False
            
            # Check if at least one profile is configured
            if not self.aws_profiles:
                logger.error("No AWS profiles configured")
                return False
            
            # Check if default profile exists
            default_profile = self.get_default_profile()
            if not default_profile:
                logger.error("Default profile not found")
                return False
            
            # Validate profile configurations
            for profile_name, profile in self.aws_profiles.items():
                if profile.type == 'access_keys':
                    if not profile.access_key_id or not profile.secret_access_key:
                        logger.error(f"Profile {profile_name}: Missing access key credentials")
                        return False
                
                elif profile.type == 'role_assumption':
                    if not profile.role_arn:
                        logger.error(f"Profile {profile_name}: Missing role ARN")
                        return False
            
            logger.info("Configuration validation passed")
            return True
            
        except Exception as e:
            logger.error(f"Configuration validation failed: {e}")
            return False

# Global secret manager instance
secret_manager = None

def get_secret_manager(config_file: str = "config/aws_credentials_config.json") -> SecretManager:
    """Get global secret manager instance"""
    global secret_manager
    if secret_manager is None:
        secret_manager = SecretManager(config_file)
    return secret_manager 
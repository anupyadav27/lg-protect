#!/usr/bin/env python3
"""
Service Configuration Loader for LG-Protect Inventory System

Enterprise-grade service configuration management with:
- Dynamic service discovery rule loading
- Configuration validation and caching
- Hot-reload capabilities
- Schema validation
- Performance optimization
"""

import json
import yaml
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, field
from pathlib import Path
import structlog
import threading
from datetime import datetime, timezone
import hashlib
import os

logger = structlog.get_logger(__name__)

@dataclass
class ServiceDiscoveryRule:
    """Individual service discovery rule"""
    resource_type: str
    api_method: str
    api_params: Dict[str, Any] = field(default_factory=dict)
    response_key: str = 'Items'
    name_field: str = 'Name'
    id_field: str = 'Id'
    arn_field: str = 'Arn'
    enabled: bool = True
    
    def validate(self) -> List[str]:
        """Validate discovery rule configuration"""
        issues = []
        
        if not self.resource_type:
            issues.append("resource_type is required")
        
        if not self.api_method:
            issues.append("api_method is required")
            
        if not self.response_key:
            issues.append("response_key is required")
            
        return issues

@dataclass
class ServiceConfig:
    """Complete service configuration"""
    service_name: str
    enabled: bool = True
    discovery_rules: List[ServiceDiscoveryRule] = field(default_factory=list)
    rate_limit_per_second: float = 10.0
    max_retries: int = 3
    timeout_seconds: int = 30
    
    # Service-specific configuration
    regional: bool = True
    global_service: bool = False
    requires_special_permissions: bool = False
    supported_regions: List[str] = field(default_factory=list)
    
    def validate(self) -> List[str]:
        """Validate service configuration"""
        issues = []
        
        if not self.service_name:
            issues.append("service_name is required")
            
        if self.rate_limit_per_second <= 0:
            issues.append("rate_limit_per_second must be positive")
            
        if self.max_retries < 0:
            issues.append("max_retries cannot be negative")
            
        if self.timeout_seconds <= 0:
            issues.append("timeout_seconds must be positive")
        
        # Validate discovery rules
        for i, rule in enumerate(self.discovery_rules):
            rule_issues = rule.validate()
            for issue in rule_issues:
                issues.append(f"discovery_rule[{i}]: {issue}")
        
        return issues

class ServiceConfigLoader:
    """
    Enterprise Service Configuration Loader
    
    Provides configuration management for AWS service discovery with:
    - Dynamic configuration loading from files
    - Configuration validation and caching
    - Hot-reload capabilities
    - Schema validation
    - Performance optimization
    """
    
    def __init__(self, config_directory: Optional[str] = None):
        self.config_directory = Path(config_directory) if config_directory else self._get_default_config_directory()
        self._config_cache: Dict[str, ServiceConfig] = {}
        self._file_checksums: Dict[str, str] = {}
        self._cache_lock = threading.RLock()
        self._last_reload_time: Optional[datetime] = None
        
        # Load configurations on initialization
        self._load_all_configurations()
        
        logger.info("service_config_loader_initialized",
                   config_directory=str(self.config_directory),
                   loaded_services=len(self._config_cache))
    
    def _get_default_config_directory(self) -> Path:
        """Get default configuration directory"""
        # Look for config directory relative to this file
        current_dir = Path(__file__).parent
        
        # Try several possible locations
        possible_paths = [
            current_dir / 'config',
            current_dir / '../config',
            current_dir / '../../config',
            current_dir / '../../../config',
            Path.cwd() / 'config'
        ]
        
        for path in possible_paths:
            if path.exists() and path.is_dir():
                return path
        
        # Create default config directory if none found
        default_path = current_dir / 'config'
        default_path.mkdir(exist_ok=True)
        self._create_default_configurations(default_path)
        
        return default_path
    
    def _create_default_configurations(self, config_dir: Path) -> None:
        """Create default service configurations"""
        default_configs = self._get_default_service_configs()
        
        for service_name, config_data in default_configs.items():
            config_file = config_dir / f"{service_name}.json"
            
            if not config_file.exists():
                with open(config_file, 'w') as f:
                    json.dump(config_data, f, indent=2)
                
                logger.debug("default_config_created",
                           service=service_name,
                           file=str(config_file))
    
    def _get_default_service_configs(self) -> Dict[str, Dict[str, Any]]:
        """Get default service configurations"""
        return {
            'ec2': {
                'service_name': 'ec2',
                'enabled': True,
                'regional': True,
                'discovery_rules': [
                    {
                        'resource_type': 'instance',
                        'api_method': 'describe_instances',
                        'api_params': {},
                        'response_key': 'Reservations',
                        'name_field': 'Tags.Name',
                        'id_field': 'InstanceId',
                        'arn_field': 'Arn'
                    },
                    {
                        'resource_type': 'vpc',
                        'api_method': 'describe_vpcs',
                        'api_params': {},
                        'response_key': 'Vpcs',
                        'name_field': 'Tags.Name',
                        'id_field': 'VpcId',
                        'arn_field': 'Arn'
                    },
                    {
                        'resource_type': 'subnet',
                        'api_method': 'describe_subnets',
                        'api_params': {},
                        'response_key': 'Subnets',
                        'name_field': 'Tags.Name',
                        'id_field': 'SubnetId',
                        'arn_field': 'Arn'
                    },
                    {
                        'resource_type': 'security-group',
                        'api_method': 'describe_security_groups',
                        'api_params': {},
                        'response_key': 'SecurityGroups',
                        'name_field': 'GroupName',
                        'id_field': 'GroupId',
                        'arn_field': 'Arn'
                    },
                    {
                        'resource_type': 'volume',
                        'api_method': 'describe_volumes',
                        'api_params': {},
                        'response_key': 'Volumes',
                        'name_field': 'Tags.Name',
                        'id_field': 'VolumeId',
                        'arn_field': 'Arn'
                    }
                ]
            },
            's3': {
                'service_name': 's3',
                'enabled': True,
                'regional': False,
                'global_service': True,
                'discovery_rules': [
                    {
                        'resource_type': 'bucket',
                        'api_method': 'list_buckets',
                        'api_params': {},
                        'response_key': 'Buckets',
                        'name_field': 'Name',
                        'id_field': 'Name',
                        'arn_field': 'Arn'
                    }
                ]
            },
            'iam': {
                'service_name': 'iam',
                'enabled': True,
                'regional': False,
                'global_service': True,
                'discovery_rules': [
                    {
                        'resource_type': 'role',
                        'api_method': 'list_roles',
                        'api_params': {},
                        'response_key': 'Roles',
                        'name_field': 'RoleName',
                        'id_field': 'RoleId',
                        'arn_field': 'Arn'
                    },
                    {
                        'resource_type': 'user',
                        'api_method': 'list_users',
                        'api_params': {},
                        'response_key': 'Users',
                        'name_field': 'UserName',
                        'id_field': 'UserId',
                        'arn_field': 'Arn'
                    },
                    {
                        'resource_type': 'policy',
                        'api_method': 'list_policies',
                        'api_params': {'Scope': 'Local'},
                        'response_key': 'Policies',
                        'name_field': 'PolicyName',
                        'id_field': 'PolicyId',
                        'arn_field': 'Arn'
                    }
                ]
            },
            'rds': {
                'service_name': 'rds',
                'enabled': True,
                'regional': True,
                'discovery_rules': [
                    {
                        'resource_type': 'db-instance',
                        'api_method': 'describe_db_instances',
                        'api_params': {},
                        'response_key': 'DBInstances',
                        'name_field': 'DBInstanceIdentifier',
                        'id_field': 'DBInstanceIdentifier',
                        'arn_field': 'DBInstanceArn'
                    },
                    {
                        'resource_type': 'db-cluster',
                        'api_method': 'describe_db_clusters',
                        'api_params': {},
                        'response_key': 'DBClusters',
                        'name_field': 'DBClusterIdentifier',
                        'id_field': 'DBClusterIdentifier',
                        'arn_field': 'DBClusterArn'
                    }
                ]
            },
            'lambda': {
                'service_name': 'lambda',
                'enabled': True,
                'regional': True,
                'discovery_rules': [
                    {
                        'resource_type': 'function',
                        'api_method': 'list_functions',
                        'api_params': {},
                        'response_key': 'Functions',
                        'name_field': 'FunctionName',
                        'id_field': 'FunctionName',
                        'arn_field': 'FunctionArn'
                    }
                ]
            },
            'kms': {
                'service_name': 'kms',
                'enabled': True,
                'regional': True,
                'discovery_rules': [
                    {
                        'resource_type': 'key',
                        'api_method': 'list_keys',
                        'api_params': {},
                        'response_key': 'Keys',
                        'name_field': 'KeyId',
                        'id_field': 'KeyId',
                        'arn_field': 'KeyArn'
                    }
                ]
            },
            'cloudformation': {
                'service_name': 'cloudformation',
                'enabled': True,
                'regional': True,
                'discovery_rules': [
                    {
                        'resource_type': 'stack',
                        'api_method': 'list_stacks',
                        'api_params': {'StackStatusFilter': ['CREATE_COMPLETE', 'UPDATE_COMPLETE']},
                        'response_key': 'StackSummaries',
                        'name_field': 'StackName',
                        'id_field': 'StackId',
                        'arn_field': 'StackId'
                    }
                ]
            }
        }
    
    def _load_all_configurations(self) -> None:
        """Load all service configurations from directory"""
        try:
            if not self.config_directory.exists():
                logger.warning("config_directory_not_found", 
                             directory=str(self.config_directory))
                return
            
            # Find all configuration files
            config_files = list(self.config_directory.glob('*.json')) + list(self.config_directory.glob('*.yaml')) + list(self.config_directory.glob('*.yml'))
            
            with self._cache_lock:
                for config_file in config_files:
                    try:
                        self._load_single_configuration(config_file)
                    except Exception as e:
                        logger.error("service_config_load_failed",
                                   file=str(config_file),
                                   error=str(e))
                
                self._last_reload_time = datetime.now(timezone.utc)
            
            logger.info("service_configurations_loaded",
                       total_configs=len(self._config_cache),
                       config_files=len(config_files))
                       
        except Exception as e:
            logger.error("service_config_loading_failed", error=str(e))
    
    def _load_single_configuration(self, config_file: Path) -> None:
        """Load a single configuration file"""
        try:
            # Calculate file checksum
            file_checksum = self._calculate_file_checksum(config_file)
            
            # Skip if file hasn't changed
            if str(config_file) in self._file_checksums and self._file_checksums[str(config_file)] == file_checksum:
                return
            
            # Load configuration data
            with open(config_file, 'r') as f:
                if config_file.suffix.lower() in ['.yaml', '.yml']:
                    config_data = yaml.safe_load(f)
                else:
                    config_data = json.load(f)
            
            # Convert to ServiceConfig object
            service_config = self._parse_service_config(config_data)
            
            # Validate configuration
            validation_issues = service_config.validate()
            if validation_issues:
                logger.error("service_config_validation_failed",
                           file=str(config_file),
                           service=service_config.service_name,
                           issues=validation_issues)
                return
            
            # Store in cache
            self._config_cache[service_config.service_name] = service_config
            self._file_checksums[str(config_file)] = file_checksum
            
            logger.debug("service_config_loaded",
                        file=str(config_file),
                        service=service_config.service_name,
                        rules_count=len(service_config.discovery_rules))
            
        except Exception as e:
            logger.error("service_config_file_load_failed",
                        file=str(config_file),
                        error=str(e))
    
    def _parse_service_config(self, config_data: Dict[str, Any]) -> ServiceConfig:
        """Parse configuration data into ServiceConfig object"""
        # Parse discovery rules
        discovery_rules = []
        for rule_data in config_data.get('discovery_rules', []):
            rule = ServiceDiscoveryRule(
                resource_type=rule_data.get('resource_type', ''),
                api_method=rule_data.get('api_method', ''),
                api_params=rule_data.get('api_params', {}),
                response_key=rule_data.get('response_key', 'Items'),
                name_field=rule_data.get('name_field', 'Name'),
                id_field=rule_data.get('id_field', 'Id'),
                arn_field=rule_data.get('arn_field', 'Arn'),
                enabled=rule_data.get('enabled', True)
            )
            discovery_rules.append(rule)
        
        # Create service config
        service_config = ServiceConfig(
            service_name=config_data.get('service_name', ''),
            enabled=config_data.get('enabled', True),
            discovery_rules=discovery_rules,
            rate_limit_per_second=config_data.get('rate_limit_per_second', 10.0),
            max_retries=config_data.get('max_retries', 3),
            timeout_seconds=config_data.get('timeout_seconds', 30),
            regional=config_data.get('regional', True),
            global_service=config_data.get('global_service', False),
            requires_special_permissions=config_data.get('requires_special_permissions', False),
            supported_regions=config_data.get('supported_regions', [])
        )
        
        return service_config
    
    def _calculate_file_checksum(self, file_path: Path) -> str:
        """Calculate checksum for configuration file"""
        try:
            with open(file_path, 'rb') as f:
                file_hash = hashlib.md5()
                for chunk in iter(lambda: f.read(4096), b""):
                    file_hash.update(chunk)
                return file_hash.hexdigest()
        except Exception:
            return str(file_path.stat().st_mtime)  # Fallback to modification time
    
    def get_service_config(self, service_name: str) -> Optional[ServiceConfig]:
        """Get configuration for a specific service"""
        with self._cache_lock:
            return self._config_cache.get(service_name)
    
    def get_all_service_configs(self) -> List[Dict[str, Any]]:
        """Get all service configurations as dictionaries"""
        with self._cache_lock:
            configs = []
            for service_config in self._config_cache.values():
                # Convert to dictionary format for discovery service
                config_dict = {
                    'service_name': service_config.service_name,
                    'enabled': service_config.enabled,
                    'regional': service_config.regional,
                    'global_service': service_config.global_service,
                    'rate_limit_per_second': service_config.rate_limit_per_second,
                    'max_retries': service_config.max_retries,
                    'timeout_seconds': service_config.timeout_seconds,
                    'discovery_rules': []
                }
                
                # Convert discovery rules
                for rule in service_config.discovery_rules:
                    if rule.enabled:
                        rule_dict = {
                            'resource_type': rule.resource_type,
                            'api_method': rule.api_method,
                            'api_params': rule.api_params,
                            'response_key': rule.response_key,
                            'name_field': rule.name_field,
                            'id_field': rule.id_field,
                            'arn_field': rule.arn_field
                        }
                        config_dict['discovery_rules'].append(rule_dict)
                
                configs.append(config_dict)
            
            return configs
    
    def get_enabled_services(self) -> List[str]:
        """Get list of enabled service names"""
        with self._cache_lock:
            return [name for name, config in self._config_cache.items() if config.enabled]
    
    def get_regional_services(self) -> List[str]:
        """Get list of regional service names"""
        with self._cache_lock:
            return [name for name, config in self._config_cache.items() if config.regional and config.enabled]
    
    def get_global_services(self) -> List[str]:
        """Get list of global service names"""
        with self._cache_lock:
            return [name for name, config in self._config_cache.items() if config.global_service and config.enabled]
    
    def reload_configurations(self) -> None:
        """Reload all configurations from disk"""
        logger.info("reloading_service_configurations")
        self._load_all_configurations()
    
    def add_service_config(self, service_config: ServiceConfig) -> None:
        """Add or update a service configuration"""
        # Validate configuration
        validation_issues = service_config.validate()
        if validation_issues:
            raise ValueError(f"Invalid service configuration: {validation_issues}")
        
        with self._cache_lock:
            self._config_cache[service_config.service_name] = service_config
        
        logger.info("service_config_added",
                   service=service_config.service_name,
                   rules_count=len(service_config.discovery_rules))
    
    def remove_service_config(self, service_name: str) -> bool:
        """Remove a service configuration"""
        with self._cache_lock:
            if service_name in self._config_cache:
                del self._config_cache[service_name]
                logger.info("service_config_removed", service=service_name)
                return True
            return False
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get configuration loader statistics"""
        with self._cache_lock:
            total_rules = sum(len(config.discovery_rules) for config in self._config_cache.values())
            enabled_services = len([c for c in self._config_cache.values() if c.enabled])
            
            return {
                'total_services': len(self._config_cache),
                'enabled_services': enabled_services,
                'disabled_services': len(self._config_cache) - enabled_services,
                'total_discovery_rules': total_rules,
                'regional_services': len(self.get_regional_services()),
                'global_services': len(self.get_global_services()),
                'config_directory': str(self.config_directory),
                'last_reload_time': self._last_reload_time.isoformat() if self._last_reload_time else None,
                'loaded_files': len(self._file_checksums)
            }
    
    def validate_all_configurations(self) -> Dict[str, List[str]]:
        """Validate all loaded configurations and return issues"""
        validation_results = {}
        
        with self._cache_lock:
            for service_name, config in self._config_cache.items():
                issues = config.validate()
                if issues:
                    validation_results[service_name] = issues
        
        return validation_results


# Singleton instance for global use
_default_service_loader = None

def get_default_service_loader() -> ServiceConfigLoader:
    """Get the default service configuration loader instance"""
    global _default_service_loader
    if _default_service_loader is None:
        _default_service_loader = ServiceConfigLoader()
    return _default_service_loader
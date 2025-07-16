#!/usr/bin/env python3
"""
Service Discovery Configuration
Integrates existing service mapping with enhanced discovery capabilities
"""

import json
import os
from typing import Dict, List, Optional, Any
from pathlib import Path
from dataclasses import dataclass
from enum import Enum

class ServiceCategory(Enum):
    """AWS Service Categories for grouped discovery"""
    COMPUTE = "compute"
    STORAGE = "storage"
    DATABASE = "database"
    NETWORK = "network"
    SECURITY = "security"
    ANALYTICS = "analytics"
    MONITORING = "monitoring"
    APPLICATION = "application"
    MANAGEMENT = "management"
    ML_AI = "ml_ai"

@dataclass
class ServiceDiscoveryRule:
    """Configuration for discovering a specific AWS service"""
    service_name: str
    boto3_client: str
    discovery_methods: List[str]
    regions_supported: List[str]
    security_checks: List[str]
    compliance_frameworks: List[str]
    resource_relationships: List[str]
    cost_tracking: bool
    criticality_level: str  # low, medium, high, critical
    category: ServiceCategory

@dataclass
class DiscoveryEngineConfig:
    """Configuration for a discovery engine handling multiple services"""
    engine_name: str
    category: ServiceCategory
    services: List[ServiceDiscoveryRule]
    priority: int  # 1-5, 1 being highest priority
    parallel_execution: bool
    max_concurrent_regions: int

class ServiceDiscoveryConfigManager:
    """Manages service discovery configuration using existing service mapping"""
    
    def __init__(self, inventory_base_path: str = "/Users/apple/Desktop/lg-protect/inventory"):
        self.inventory_base_path = inventory_base_path
        self.service_mapping_file = os.path.join(inventory_base_path, "config", "service_enablement_mapping.json")
        self.service_mapping: Dict[str, Any] = {}
        self.discovery_rules: Dict[str, ServiceDiscoveryRule] = {}
        self.engine_configs: Dict[ServiceCategory, DiscoveryEngineConfig] = {}
        
        self._load_service_mapping()
        self._create_discovery_rules()
        self._create_engine_configs()
    
    def _load_service_mapping(self):
        """Load existing service enablement mapping"""
        try:
            with open(self.service_mapping_file, 'r') as f:
                self.service_mapping = json.load(f)
        except FileNotFoundError:
            raise FileNotFoundError(f"Service mapping file not found: {self.service_mapping_file}")
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in service mapping file: {e}")
    
    def _create_discovery_rules(self):
        """Create discovery rules from existing service mapping"""
        
        # Category mapping from string to enum
        category_enum_mapping = {
            'compute': ServiceCategory.COMPUTE,
            'storage': ServiceCategory.STORAGE,
            'database': ServiceCategory.DATABASE,
            'network': ServiceCategory.NETWORK,
            'security': ServiceCategory.SECURITY,
            'analytics': ServiceCategory.ANALYTICS,
            'monitoring': ServiceCategory.MONITORING,
            'application': ServiceCategory.APPLICATION,
            'management': ServiceCategory.MANAGEMENT,
            'ml_ai': ServiceCategory.ML_AI,
        }
        
        # Create discovery rules for each service in the mapping
        for service_name, service_info in self.service_mapping.items():
            # Get category from service mapping
            category_str = service_info.get('category', 'application')
            category_enum = category_enum_mapping.get(category_str, ServiceCategory.APPLICATION)
            
            self.discovery_rules[service_name] = self._create_service_rule(
                service_name, service_info, category_enum
            )
    
    def _create_service_rule(self, service_name: str, service_info: Dict, category: ServiceCategory) -> ServiceDiscoveryRule:
        """Create a discovery rule for a specific service"""
        
        # Define security checks based on service type and category
        security_checks = self._get_security_checks_for_service(service_name, category)
        
        # Define compliance frameworks
        compliance_frameworks = self._get_compliance_frameworks_for_service(service_name, category)
        
        # Define relationships
        relationships = self._get_relationships_for_service(service_name, category)
        
        # Determine criticality based on service type
        criticality = self._get_criticality_for_service(service_name, category)
        
        return ServiceDiscoveryRule(
            service_name=service_name,
            boto3_client=service_info.get('boto3_client', service_name),
            discovery_methods=service_info.get('discovery_methods', [f'list_{service_name}_resources']),
            regions_supported=service_info.get('regions', ['us-east-1', 'us-west-2', 'eu-west-1']),
            security_checks=security_checks,
            compliance_frameworks=compliance_frameworks,
            resource_relationships=relationships,
            cost_tracking=service_info.get('cost_tracking', True),
            criticality_level=criticality,
            category=category
        )
    
    def _get_security_checks_for_service(self, service_name: str, category: ServiceCategory) -> List[str]:
        """Define security checks based on service and category"""
        
        common_checks = ['public_access', 'encryption_at_rest', 'encryption_in_transit', 'access_logging']
        
        service_specific_checks = {
            's3': ['bucket_public_read', 'bucket_public_write', 'bucket_ssl_only', 'bucket_versioning'],
            'ec2': ['security_groups_open', 'public_ip_assigned', 'imdsv2_enforced', 'ebs_encryption'],
            'rds': ['public_accessibility', 'backup_enabled', 'multi_az', 'deletion_protection'],
            'iam': ['unused_roles', 'overprivileged_policies', 'mfa_enabled', 'password_policy'],
            'kms': ['key_rotation_enabled', 'key_policy_restrictions'],
            'lambda': ['runtime_outdated', 'environment_secrets', 'vpc_configuration'],
            'vpc': ['flow_logs_enabled', 'default_security_group', 'nacl_rules'],
        }
        
        return common_checks + service_specific_checks.get(service_name, [])
    
    def _get_compliance_frameworks_for_service(self, service_name: str, category: ServiceCategory) -> List[str]:
        """Define compliance frameworks applicable to each service"""
        
        all_services_frameworks = ['CIS', 'AWS_Config', 'AWS_Foundational_Security_Standard']
        
        category_frameworks = {
            ServiceCategory.SECURITY: ['SOC2', 'ISO27001', 'PCI_DSS', 'HIPAA'],
            ServiceCategory.DATABASE: ['PCI_DSS', 'HIPAA', 'GDPR'],
            ServiceCategory.STORAGE: ['PCI_DSS', 'HIPAA', 'GDPR'],
            ServiceCategory.COMPUTE: ['CIS_Benchmarks'],
            ServiceCategory.NETWORK: ['NIST_Cybersecurity_Framework'],
        }
        
        return all_services_frameworks + category_frameworks.get(category, [])
    
    def _get_relationships_for_service(self, service_name: str, category: ServiceCategory) -> List[str]:
        """Define resource relationships for each service"""
        
        relationships_map = {
            'ec2': ['vpc', 'security_groups', 'iam_roles', 'ebs_volumes', 'elastic_ips'],
            's3': ['iam_policies', 'kms_keys', 'cloudfront_distributions'],
            'rds': ['vpc', 'security_groups', 'kms_keys', 'iam_roles'],
            'lambda': ['iam_roles', 'vpc', 'api_gateway', 'cloudwatch_logs'],
            'iam': ['all_services'],  # IAM can relate to any service
            'vpc': ['ec2', 'rds', 'lambda', 'load_balancers'],
            'kms': ['s3', 'rds', 'ebs', 'secrets_manager'],
        }
        
        return relationships_map.get(service_name, [])
    
    def _get_criticality_for_service(self, service_name: str, category: ServiceCategory) -> str:
        """Determine criticality level for service"""
        
        critical_services = ['iam', 'kms', 'guardduty', 'securityhub']
        high_services = ['ec2', 's3', 'rds', 'vpc', 'lambda']
        medium_services = ['cloudwatch', 'cloudtrail', 'sns', 'sqs']
        
        if service_name in critical_services:
            return 'critical'
        elif service_name in high_services:
            return 'high'
        elif service_name in medium_services:
            return 'medium'
        else:
            return 'low'
    
    def _create_engine_configs(self):
        """Create discovery engine configurations grouped by category"""
        
        # Group services by category
        services_by_category: Dict[ServiceCategory, List[ServiceDiscoveryRule]] = {}
        for rule in self.discovery_rules.values():
            if rule.category not in services_by_category:
                services_by_category[rule.category] = []
            services_by_category[rule.category].append(rule)
        
        # Create engine configs
        engine_priorities = {
            ServiceCategory.SECURITY: 1,      # Highest priority
            ServiceCategory.COMPUTE: 2,
            ServiceCategory.NETWORK: 2,
            ServiceCategory.DATABASE: 3,
            ServiceCategory.STORAGE: 3,
            ServiceCategory.MONITORING: 4,
            ServiceCategory.APPLICATION: 4,
            ServiceCategory.ANALYTICS: 5,
            ServiceCategory.MANAGEMENT: 5,
            ServiceCategory.ML_AI: 5,
        }
        
        for category, services in services_by_category.items():
            self.engine_configs[category] = DiscoveryEngineConfig(
                engine_name=f"{category.value}_discovery_engine",
                category=category,
                services=services,
                priority=engine_priorities.get(category, 5),
                parallel_execution=True,
                max_concurrent_regions=3 if category in [ServiceCategory.SECURITY, ServiceCategory.COMPUTE] else 5
            )
    
    def get_discovery_rule(self, service_name: str) -> Optional[ServiceDiscoveryRule]:
        """Get discovery rule for a specific service"""
        return self.discovery_rules.get(service_name)
    
    def get_engine_config(self, category: ServiceCategory) -> Optional[DiscoveryEngineConfig]:
        """Get engine configuration for a category"""
        return self.engine_configs.get(category)
    
    def get_services_for_category(self, category: ServiceCategory) -> List[ServiceDiscoveryRule]:
        """Get all services for a specific category"""
        return [rule for rule in self.discovery_rules.values() if rule.category == category]
    
    def get_high_priority_services(self) -> List[ServiceDiscoveryRule]:
        """Get services marked as high or critical priority"""
        return [rule for rule in self.discovery_rules.values() 
                if rule.criticality_level in ['high', 'critical']]
    
    def get_security_focused_services(self) -> List[ServiceDiscoveryRule]:
        """Get services that are security-focused"""
        return self.get_services_for_category(ServiceCategory.SECURITY)
    
    def export_config(self, output_path: str):
        """Export configuration to JSON file"""
        config_data = {
            'discovery_rules': {
                name: {
                    'service_name': rule.service_name,
                    'boto3_client': rule.boto3_client,
                    'discovery_methods': rule.discovery_methods,
                    'regions_supported': rule.regions_supported,
                    'security_checks': rule.security_checks,
                    'compliance_frameworks': rule.compliance_frameworks,
                    'resource_relationships': rule.resource_relationships,
                    'cost_tracking': rule.cost_tracking,
                    'criticality_level': rule.criticality_level,
                    'category': rule.category.value
                }
                for name, rule in self.discovery_rules.items()
            },
            'engine_configs': {
                category.value: {
                    'engine_name': config.engine_name,
                    'category': config.category.value,
                    'service_count': len(config.services),
                    'priority': config.priority,
                    'parallel_execution': config.parallel_execution,
                    'max_concurrent_regions': config.max_concurrent_regions
                }
                for category, config in self.engine_configs.items()
            }
        }
        
        with open(output_path, 'w') as f:
            json.dump(config_data, f, indent=2)
    
    def get_enabled_services(self, tenant_id: str) -> List[str]:
        """
        Integration point with existing service enablement checker
        This method would call the existing simplified_service_enablement_checker.py
        """
        # This will be implemented to integrate with existing service detection
        # For now, return all services
        return list(self.discovery_rules.keys())


# Initialize global configuration manager
config_manager = ServiceDiscoveryConfigManager()

def get_config_manager() -> ServiceDiscoveryConfigManager:
    """Get the global configuration manager instance"""
    return config_manager
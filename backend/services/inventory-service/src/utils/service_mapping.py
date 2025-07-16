#!/usr/bin/env python3
"""
Service Configuration Loader for LG-Protect Inventory System

Transforms existing service mapping configurations into enhanced discovery rules
with security analysis capabilities and enterprise-grade error handling.
"""

import json
import os
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import structlog

logger = structlog.get_logger(__name__)

class ServiceScope(Enum):
    """Service scope enumeration"""
    GLOBAL = "global"
    REGIONAL = "regional" 
    MULTI_REGION = "multi_region"

class SecurityAnalysisType(Enum):
    """Types of security analysis for services"""
    PUBLIC_EXPOSURE = "public_exposure"
    ENCRYPTION_STATUS = "encryption_status"
    ACCESS_CONTROL = "access_control"
    NETWORK_SECURITY = "network_security"
    CONFIGURATION_DRIFT = "configuration_drift"
    COMPLIANCE_CHECK = "compliance_check"
    VULNERABILITY_SCAN = "vulnerability_scan"

@dataclass
class ServiceDiscoveryMethod:
    """Configuration for a specific discovery method"""
    method_name: str
    api_function: str
    response_field: str
    resource_identifier: str
    security_analysis: List[SecurityAnalysisType] = field(default_factory=list)
    additional_calls: List[str] = field(default_factory=list)
    rate_limit_delay: float = 0.1
    
    def __post_init__(self):
        """Validate discovery method configuration"""
        if not self.method_name:
            raise ValueError("Method name is required")
        if not self.api_function:
            raise ValueError("API function is required")

@dataclass
class ServiceRelationshipConfig:
    """Configuration for service relationships"""
    target_service: str
    relationship_type: str
    discovery_method: str = ""
    conditions: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ServiceConfiguration:
    """Enhanced service configuration with discovery rules"""
    service_name: str
    client_type: str
    scope: ServiceScope
    asset_type: str
    regions: List[str] = field(default_factory=list)
    
    # Discovery methods
    discovery_methods: List[ServiceDiscoveryMethod] = field(default_factory=list)
    
    # Security analysis
    security_checks: List[SecurityAnalysisType] = field(default_factory=list)
    compliance_frameworks: List[str] = field(default_factory=list)
    
    # Relationships
    relationships: List[ServiceRelationshipConfig] = field(default_factory=list)
    
    # Performance & Rate Limiting
    parallel_regions: bool = True
    max_concurrent_calls: int = 5
    retry_attempts: int = 3
    timeout_seconds: int = 30
    
    # Metadata
    priority: int = 1  # 1=high, 2=medium, 3=low
    enabled: bool = True

class ServiceMappingLoader:
    """
    Enterprise-grade service configuration loader
    
    Transforms basic service mappings into comprehensive discovery configurations
    with security analysis, relationship mapping, and performance optimization.
    """
    
    def __init__(self, config_dir: Optional[str] = None):
        """
        Initialize service mapping loader
        
        Args:
            config_dir: Directory containing configuration files
        """
        self.config_dir = config_dir or self._get_default_config_dir()
        self.service_configs: Dict[str, ServiceConfiguration] = {}
        self.loaded = False
        
        # Asset type mapping for services
        self.asset_type_mapping = {
            # Compute services
            'ec2': 'compute',
            'lambda': 'serverless',
            'ecs': 'container',
            'eks': 'container',
            'autoscaling': 'compute',
            'emr': 'analytics',
            'sagemaker': 'analytics',
            
            # Storage services
            's3': 'storage',
            'ebs': 'storage',
            'efs': 'storage',
            'fsx': 'storage',
            'glacier': 'storage',
            'backup': 'storage',
            'storagegateway': 'storage',
            
            # Database services
            'rds': 'database',
            'dynamodb': 'database',
            'redshift': 'database',
            'elasticache': 'database',
            
            # Network services
            'vpc': 'network',
            'cloudfront': 'network',
            'route53': 'network',
            'elbv2': 'network',
            'directconnect': 'network',
            'globalaccelerator': 'network',
            'apigateway': 'network',
            'apigatewayv2': 'network',
            'vpc-lattice': 'network',
            
            # Security services
            'iam': 'identity',
            'kms': 'security',
            'guardduty': 'security',
            'securityhub': 'security',
            'inspector2': 'security',
            'secretsmanager': 'security',
            'waf': 'security',
            'wafv2': 'security',
            'shield': 'security',
            
            # Monitoring services
            'cloudwatch': 'monitoring',
            'cloudtrail': 'monitoring',
            'config': 'monitoring',
            'logs': 'monitoring',
            
            # Application services
            'sns': 'application',
            'sqs': 'application',
            'events': 'application',
            'stepfunctions': 'application',
            'kinesis': 'analytics',
            'firehose': 'analytics',
            'glue': 'analytics',
            'athena': 'analytics',
            
            # Management services
            'cloudformation': 'management',
            'ssm': 'management',
            'organizations': 'management',
            'transfer': 'management',
            'datasync': 'management'
        }
        
        # Security analysis mapping for services
        self.security_analysis_mapping = {
            's3': [SecurityAnalysisType.PUBLIC_EXPOSURE, SecurityAnalysisType.ENCRYPTION_STATUS, SecurityAnalysisType.ACCESS_CONTROL],
            'ec2': [SecurityAnalysisType.PUBLIC_EXPOSURE, SecurityAnalysisType.NETWORK_SECURITY, SecurityAnalysisType.ACCESS_CONTROL],
            'rds': [SecurityAnalysisType.PUBLIC_EXPOSURE, SecurityAnalysisType.ENCRYPTION_STATUS, SecurityAnalysisType.NETWORK_SECURITY],
            'iam': [SecurityAnalysisType.ACCESS_CONTROL, SecurityAnalysisType.COMPLIANCE_CHECK],
            'lambda': [SecurityAnalysisType.ACCESS_CONTROL, SecurityAnalysisType.NETWORK_SECURITY],
            'elbv2': [SecurityAnalysisType.PUBLIC_EXPOSURE, SecurityAnalysisType.NETWORK_SECURITY],
            'cloudfront': [SecurityAnalysisType.PUBLIC_EXPOSURE, SecurityAnalysisType.ACCESS_CONTROL],
            'apigateway': [SecurityAnalysisType.PUBLIC_EXPOSURE, SecurityAnalysisType.ACCESS_CONTROL],
            'guardduty': [SecurityAnalysisType.VULNERABILITY_SCAN, SecurityAnalysisType.COMPLIANCE_CHECK],
            'securityhub': [SecurityAnalysisType.VULNERABILITY_SCAN, SecurityAnalysisType.COMPLIANCE_CHECK],
            'kms': [SecurityAnalysisType.ENCRYPTION_STATUS, SecurityAnalysisType.ACCESS_CONTROL]
        }
    
    def _get_default_config_dir(self) -> str:
        """Get default configuration directory"""
        try:
            # Use the inventory directory with service mappings
            current_file = Path(__file__).parent.parent.parent.parent.parent
            inventory_dir = current_file / "inventory"
            
            if inventory_dir.exists():
                return str(inventory_dir)
            else:
                # Fallback to relative path
                return "/Users/apple/Desktop/lg-protect/inventory"
                
        except Exception as e:
            logger.warning("default_config_dir_detection_failed", error=str(e))
            return "/Users/apple/Desktop/lg-protect/inventory"
    
    async def load_service_configurations(self) -> bool:
        """
        Load and transform service configurations
        
        Returns:
            bool: True if configurations loaded successfully
        """
        try:
            logger.info("loading_service_configurations", config_dir=self.config_dir)
            
            # Load basic service mapping
            basic_mapping = await self._load_basic_service_mapping()
            if not basic_mapping:
                logger.error("failed_to_load_basic_service_mapping")
                return False
            
            # Transform to enhanced configurations
            for service_name, service_config in basic_mapping.items():
                try:
                    enhanced_config = self._transform_service_config(service_name, service_config)
                    self.service_configs[service_name] = enhanced_config
                    
                    logger.debug("service_config_transformed", 
                               service_name=service_name,
                               discovery_methods=len(enhanced_config.discovery_methods),
                               security_checks=len(enhanced_config.security_checks))
                               
                except Exception as e:
                    logger.error("service_config_transformation_failed", 
                               service_name=service_name, 
                               error=str(e))
                    continue
            
            self.loaded = True
            logger.info("service_configurations_loaded", 
                       total_services=len(self.service_configs),
                       enabled_services=len([s for s in self.service_configs.values() if s.enabled]))
            
            return True
            
        except Exception as e:
            logger.error("service_configuration_loading_failed", error=str(e))
            return False
    
    async def _load_basic_service_mapping(self) -> Optional[Dict[str, Any]]:
        """Load basic service mapping from JSON file"""
        try:
            mapping_file = Path(self.config_dir) / "service_enablement_mapping.json"
            
            if not mapping_file.exists():
                logger.error("service_mapping_file_not_found", file_path=str(mapping_file))
                return None
            
            with open(mapping_file, 'r') as f:
                mapping_data = json.load(f)
            
            logger.info("basic_service_mapping_loaded", 
                       services_count=len(mapping_data),
                       file_path=str(mapping_file))
            
            return mapping_data
            
        except Exception as e:
            logger.error("basic_service_mapping_load_failed", error=str(e))
            return None
    
    def _transform_service_config(self, service_name: str, basic_config: Dict[str, Any]) -> ServiceConfiguration:
        """Transform basic service config to enhanced configuration"""
        try:
            # Determine scope
            scope = ServiceScope.REGIONAL
            if basic_config.get('scope') == 'global':
                scope = ServiceScope.GLOBAL
            elif 'regions' not in basic_config:
                scope = ServiceScope.GLOBAL
            
            # Get asset type
            asset_type = self.asset_type_mapping.get(service_name, 'unknown')
            
            # Create main discovery method
            main_method = ServiceDiscoveryMethod(
                method_name=f"discover_{service_name}_resources",
                api_function=basic_config.get('check_function', ''),
                response_field=basic_config.get('count_field', ''),
                resource_identifier=basic_config.get('resource_identifier', 'id'),
                security_analysis=self.security_analysis_mapping.get(service_name, [])
            )
            
            # Add additional discovery methods based on service type
            additional_methods = self._get_additional_discovery_methods(service_name)
            
            # Get security checks
            security_checks = self.security_analysis_mapping.get(service_name, [])
            
            # Get compliance frameworks (all services support these by default)
            compliance_frameworks = ['cis', 'soc2', 'nist', 'aws_foundational']
            
            # Add service-specific compliance frameworks
            if service_name in ['s3', 'rds', 'dynamodb']:
                compliance_frameworks.append('hipaa')
            if service_name in ['s3', 'ec2', 'rds']:
                compliance_frameworks.append('pci_dss')
            
            # Get relationships
            relationships = self._get_service_relationships(service_name)
            
            # Determine priority
            priority = self._get_service_priority(service_name, asset_type)
            
            enhanced_config = ServiceConfiguration(
                service_name=service_name,
                client_type=basic_config.get('client_type', service_name),
                scope=scope,
                asset_type=asset_type,
                regions=basic_config.get('regions', []),
                discovery_methods=[main_method] + additional_methods,
                security_checks=security_checks,
                compliance_frameworks=compliance_frameworks,
                relationships=relationships,
                priority=priority,
                enabled=True
            )
            
            return enhanced_config
            
        except Exception as e:
            logger.error("service_config_transformation_error", 
                        service_name=service_name, 
                        error=str(e))
            raise
    
    def _get_additional_discovery_methods(self, service_name: str) -> List[ServiceDiscoveryMethod]:
        """Get additional discovery methods for comprehensive asset discovery"""
        additional_methods = []
        
        try:
            # Service-specific additional methods
            if service_name == 'ec2':
                additional_methods.extend([
                    ServiceDiscoveryMethod(
                        method_name="discover_ec2_security_groups",
                        api_function="describe_security_groups",
                        response_field="SecurityGroups[*].GroupId",
                        resource_identifier="GroupId",
                        security_analysis=[SecurityAnalysisType.NETWORK_SECURITY]
                    ),
                    ServiceDiscoveryMethod(
                        method_name="discover_ec2_volumes",
                        api_function="describe_volumes",
                        response_field="Volumes[*].VolumeId",
                        resource_identifier="VolumeId",
                        security_analysis=[SecurityAnalysisType.ENCRYPTION_STATUS]
                    )
                ])
            
            elif service_name == 's3':
                additional_methods.extend([
                    ServiceDiscoveryMethod(
                        method_name="discover_s3_bucket_policies",
                        api_function="get_bucket_policy",
                        response_field="Policy",
                        resource_identifier="bucket_name",
                        security_analysis=[SecurityAnalysisType.ACCESS_CONTROL]
                    ),
                    ServiceDiscoveryMethod(
                        method_name="discover_s3_bucket_encryption",
                        api_function="get_bucket_encryption",
                        response_field="ServerSideEncryptionConfiguration",
                        resource_identifier="bucket_name",
                        security_analysis=[SecurityAnalysisType.ENCRYPTION_STATUS]
                    )
                ])
            
            elif service_name == 'iam':
                additional_methods.extend([
                    ServiceDiscoveryMethod(
                        method_name="discover_iam_roles",
                        api_function="list_roles",
                        response_field="Roles[*].RoleName",
                        resource_identifier="RoleName",
                        security_analysis=[SecurityAnalysisType.ACCESS_CONTROL]
                    ),
                    ServiceDiscoveryMethod(
                        method_name="discover_iam_policies",
                        api_function="list_policies",
                        response_field="Policies[*].PolicyName",
                        resource_identifier="PolicyName",
                        security_analysis=[SecurityAnalysisType.ACCESS_CONTROL]
                    )
                ])
            
            elif service_name == 'rds':
                additional_methods.extend([
                    ServiceDiscoveryMethod(
                        method_name="discover_rds_clusters",
                        api_function="describe_db_clusters",
                        response_field="DBClusters[*].DBClusterIdentifier",
                        resource_identifier="DBClusterIdentifier",
                        security_analysis=[SecurityAnalysisType.ENCRYPTION_STATUS, SecurityAnalysisType.NETWORK_SECURITY]
                    ),
                    ServiceDiscoveryMethod(
                        method_name="discover_rds_snapshots",
                        api_function="describe_db_snapshots",
                        response_field="DBSnapshots[*].DBSnapshotIdentifier",
                        resource_identifier="DBSnapshotIdentifier",
                        security_analysis=[SecurityAnalysisType.ENCRYPTION_STATUS]
                    )
                ])
            
        except Exception as e:
            logger.error("additional_discovery_methods_failed", 
                        service_name=service_name, 
                        error=str(e))
        
        return additional_methods
    
    def _get_service_relationships(self, service_name: str) -> List[ServiceRelationshipConfig]:
        """Get relationship configurations for a service"""
        relationships = []
        
        try:
            # Define common relationships
            relationship_mappings = {
                'ec2': [
                    ServiceRelationshipConfig('vpc', 'contained_in'),
                    ServiceRelationshipConfig('iam', 'managed_by'),
                    ServiceRelationshipConfig('ebs', 'has_part')
                ],
                's3': [
                    ServiceRelationshipConfig('iam', 'accessed_by'),
                    ServiceRelationshipConfig('kms', 'protected_by')
                ],
                'lambda': [
                    ServiceRelationshipConfig('vpc', 'contained_in'),
                    ServiceRelationshipConfig('iam', 'managed_by'),
                    ServiceRelationshipConfig('s3', 'accesses')
                ],
                'rds': [
                    ServiceRelationshipConfig('vpc', 'contained_in'),
                    ServiceRelationshipConfig('kms', 'protected_by'),
                    ServiceRelationshipConfig('ec2', 'connected_from')
                ],
                'elbv2': [
                    ServiceRelationshipConfig('vpc', 'contained_in'),
                    ServiceRelationshipConfig('ec2', 'connects_to')
                ]
            }
            
            relationships = relationship_mappings.get(service_name, [])
            
        except Exception as e:
            logger.error("service_relationships_failed", 
                        service_name=service_name, 
                        error=str(e))
        
        return relationships
    
    def _get_service_priority(self, service_name: str, asset_type: str) -> int:
        """Determine service priority for discovery ordering"""
        try:
            # High priority services (discover first)
            high_priority = ['ec2', 's3', 'iam', 'vpc', 'rds', 'lambda']
            
            # Medium priority services
            medium_priority = ['elbv2', 'cloudfront', 'route53', 'kms', 'guardduty', 'securityhub']
            
            if service_name in high_priority:
                return 1
            elif service_name in medium_priority:
                return 2
            else:
                return 3
                
        except Exception as e:
            logger.error("service_priority_calculation_failed", 
                        service_name=service_name, 
                        error=str(e))
            return 3
    
    def get_service_config(self, service_name: str) -> Optional[ServiceConfiguration]:
        """Get configuration for a specific service"""
        if not self.loaded:
            logger.warning("service_configs_not_loaded", service_name=service_name)
            return None
        
        return self.service_configs.get(service_name)
    
    def get_services_by_priority(self, priority: int) -> List[ServiceConfiguration]:
        """Get services by priority level"""
        if not self.loaded:
            logger.warning("service_configs_not_loaded")
            return []
        
        return [config for config in self.service_configs.values() 
                if config.priority == priority and config.enabled]
    
    def get_services_by_asset_type(self, asset_type: str) -> List[ServiceConfiguration]:
        """Get services by asset type"""
        if not self.loaded:
            logger.warning("service_configs_not_loaded")
            return []
        
        return [config for config in self.service_configs.values() 
                if config.asset_type == asset_type and config.enabled]
    
    def get_global_services(self) -> List[ServiceConfiguration]:
        """Get global scope services"""
        if not self.loaded:
            logger.warning("service_configs_not_loaded")
            return []
        
        return [config for config in self.service_configs.values() 
                if config.scope == ServiceScope.GLOBAL and config.enabled]
    
    def get_regional_services(self) -> List[ServiceConfiguration]:
        """Get regional scope services"""
        if not self.loaded:
            logger.warning("service_configs_not_loaded")
            return []
        
        return [config for config in self.service_configs.values() 
                if config.scope == ServiceScope.REGIONAL and config.enabled]
    
    def get_services_with_security_analysis(self, analysis_type: SecurityAnalysisType) -> List[ServiceConfiguration]:
        """Get services that support specific security analysis"""
        if not self.loaded:
            logger.warning("service_configs_not_loaded")
            return []
        
        return [config for config in self.service_configs.values() 
                if analysis_type in config.security_checks and config.enabled]
    
    def get_discovery_statistics(self) -> Dict[str, Any]:
        """Get statistics about loaded service configurations"""
        if not self.loaded:
            return {"error": "Service configurations not loaded"}
        
        try:
            stats = {
                "total_services": len(self.service_configs),
                "enabled_services": len([s for s in self.service_configs.values() if s.enabled]),
                "by_priority": {
                    "high": len(self.get_services_by_priority(1)),
                    "medium": len(self.get_services_by_priority(2)),
                    "low": len(self.get_services_by_priority(3))
                },
                "by_scope": {
                    "global": len(self.get_global_services()),
                    "regional": len(self.get_regional_services())
                },
                "by_asset_type": {},
                "security_analysis_coverage": {},
                "compliance_frameworks": set()
            }
            
            # Asset type breakdown
            for asset_type in set(self.asset_type_mapping.values()):
                stats["by_asset_type"][asset_type] = len(self.get_services_by_asset_type(asset_type))
            
            # Security analysis coverage
            for analysis_type in SecurityAnalysisType:
                services_count = len(self.get_services_with_security_analysis(analysis_type))
                stats["security_analysis_coverage"][analysis_type.value] = services_count
            
            # Compliance frameworks
            for config in self.service_configs.values():
                stats["compliance_frameworks"].update(config.compliance_frameworks)
            stats["compliance_frameworks"] = list(stats["compliance_frameworks"])
            
            return stats
            
        except Exception as e:
            logger.error("discovery_statistics_failed", error=str(e))
            return {"error": str(e)}
    
    def validate_configurations(self) -> Tuple[bool, List[str]]:
        """Validate all loaded configurations"""
        if not self.loaded:
            return False, ["Service configurations not loaded"]
        
        issues = []
        
        try:
            for service_name, config in self.service_configs.items():
                # Validate discovery methods
                for method in config.discovery_methods:
                    if not method.api_function:
                        issues.append(f"{service_name}: Missing API function for method {method.method_name}")
                    if not method.response_field:
                        issues.append(f"{service_name}: Missing response field for method {method.method_name}")
                
                # Validate regional services have regions
                if config.scope == ServiceScope.REGIONAL and not config.regions:
                    issues.append(f"{service_name}: Regional service missing regions list")
                
                # Validate client type
                if not config.client_type:
                    issues.append(f"{service_name}: Missing client type")
            
            is_valid = len(issues) == 0
            
            logger.info("configuration_validation_completed", 
                       is_valid=is_valid, 
                       issues_count=len(issues))
            
            return is_valid, issues
            
        except Exception as e:
            logger.error("configuration_validation_failed", error=str(e))
            return False, [f"Validation failed: {str(e)}"]
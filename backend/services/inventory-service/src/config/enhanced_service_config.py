#!/usr/bin/env python3
"""
Enhanced Service Configuration System for LG-Protect

Extends the existing service_enablement_mapping.json with enterprise features:
- Security analysis configurations
- Compliance framework mappings  
- Asset relationship definitions
- Risk scoring parameters
- Discovery optimization settings
"""

import json
import asyncio
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, field
from pathlib import Path
import structlog
from enum import Enum

logger = structlog.get_logger(__name__)

class SecurityAnalysisType(Enum):
    """Types of security analysis to perform on assets"""
    ENCRYPTION_STATUS = "encryption_status"
    ACCESS_CONTROL = "access_control"
    NETWORK_SECURITY = "network_security"
    COMPLIANCE_CHECK = "compliance_check"
    VULNERABILITY_SCAN = "vulnerability_scan"
    CONFIGURATION_AUDIT = "configuration_audit"
    DATA_PROTECTION = "data_protection"

class ComplianceFramework(Enum):
    """Supported compliance frameworks"""
    SOC2 = "soc2"
    PCI_DSS = "pci_dss"
    HIPAA = "hipaa"
    GDPR = "gdpr"
    AWS_FOUNDATIONAL = "aws_foundational"
    CIS_BENCHMARK = "cis_benchmark"
    NIST_CSF = "nist_csf"
    ISO_27001 = "iso_27001"

class ServiceCategory(Enum):
    """Service categories for discovery engine organization"""
    COMPUTE = "compute"
    STORAGE = "storage"
    DATABASE = "database"
    NETWORK = "network"
    SECURITY = "security"
    MONITORING = "monitoring"
    ANALYTICS = "analytics"
    APPLICATION = "application"
    MANAGEMENT = "management"
    ML_AI = "ml_ai"
    IDENTITY = "identity"

@dataclass
class SecurityAnalysisConfig:
    """Configuration for security analysis of a service"""
    analysis_types: List[SecurityAnalysisType]
    priority: int = 3  # 1=highest, 5=lowest
    specific_checks: List[str] = field(default_factory=list)
    compliance_mappings: Dict[ComplianceFramework, List[str]] = field(default_factory=dict)
    
    def __post_init__(self):
        if not self.specific_checks:
            self.specific_checks = []
        if not self.compliance_mappings:
            self.compliance_mappings = {}

@dataclass
class ServiceRelationshipConfig:
    """Configuration for asset relationships"""
    relationship_type: str  # 'depends_on', 'contains', 'attached_to', 'manages'
    target_services: List[str]
    relationship_fields: List[str]  # Fields that contain relationship identifiers
    bidirectional: bool = False

@dataclass
class ServiceDiscoveryMethod:
    """Additional discovery method configuration"""
    method_name: str
    api_function: str
    response_field: str
    resource_identifier: str
    security_analysis: List[SecurityAnalysisType] = field(default_factory=list)
    priority: int = 3

@dataclass
class EnhancedServiceConfiguration:
    """Complete service configuration with enterprise features"""
    # Base configuration (from existing mapping)
    service_name: str
    client_type: str
    check_function: str
    count_field: str
    resource_identifier: str
    scope: str
    regions: List[str]
    
    # Enhanced enterprise features
    category: ServiceCategory
    security_analysis: SecurityAnalysisConfig
    relationships: List[ServiceRelationshipConfig] = field(default_factory=list)
    additional_discovery_methods: List[ServiceDiscoveryMethod] = field(default_factory=list)
    
    # Discovery optimization
    discovery_priority: int = 3  # 1=highest, 5=lowest
    parallel_discovery: bool = True
    max_concurrent_regions: int = 3
    rate_limit_rpm: int = 100  # Requests per minute
    
    # Asset enrichment
    enable_detailed_analysis: bool = True
    enable_relationship_mapping: bool = True
    enable_compliance_scoring: bool = True
    
    def __post_init__(self):
        if not self.relationships:
            self.relationships = []
        if not self.additional_discovery_methods:
            self.additional_discovery_methods = []

class EnhancedServiceConfigurationLoader:
    """
    Loads and enhances service configurations with enterprise features
    
    Takes the basic service_enablement_mapping.json and adds:
    - Security analysis configurations
    - Compliance framework mappings
    - Asset relationship definitions
    - Discovery optimization settings
    """
    
    def __init__(self, config_dir: Optional[str] = None):
        self.config_dir = config_dir or "/Users/apple/Desktop/lg-protect/inventory"
        self.base_mapping_file = Path(self.config_dir) / "service_enablement_mapping.json"
        self.enhanced_configs: Dict[str, EnhancedServiceConfiguration] = {}
        self.loaded = False
        
        logger.info("enhanced_service_config_loader_initialized", 
                   config_dir=self.config_dir)
    
    async def load_enhanced_configurations(self) -> bool:
        """Load and enhance all service configurations"""
        try:
            # Load base service mapping
            base_mapping = await self._load_base_mapping()
            if not base_mapping:
                return False
            
            logger.info("enhancing_service_configurations",
                       base_services_count=len(base_mapping))
            
            # Enhance each service configuration
            for service_name, base_config in base_mapping.items():
                try:
                    enhanced_config = self._enhance_service_config(service_name, base_config)
                    self.enhanced_configs[service_name] = enhanced_config
                    
                    logger.debug("service_config_enhanced",
                               service_name=service_name,
                               category=enhanced_config.category.value,
                               security_analyses=len(enhanced_config.security_analysis.analysis_types),
                               relationships=len(enhanced_config.relationships))
                               
                except Exception as e:
                    logger.error("service_config_enhancement_failed",
                               service_name=service_name,
                               error=str(e))
                    continue
            
            self.loaded = True
            
            # Log enhancement summary
            logger.info("service_configurations_enhanced_successfully",
                       total_enhanced=len(self.enhanced_configs),
                       by_category=self._get_category_distribution(),
                       high_priority_services=len(self.get_high_priority_services()),
                       security_focused_services=len(self.get_security_focused_services()))
            
            return True
            
        except Exception as e:
            logger.error("enhanced_configuration_loading_failed", error=str(e))
            return False
    
    async def _load_base_mapping(self) -> Optional[Dict[str, Any]]:
        """Load base service mapping from JSON"""
        try:
            with open(self.base_mapping_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error("base_mapping_loading_failed", 
                        file=str(self.base_mapping_file),
                        error=str(e))
            return None
    
    def _enhance_service_config(self, service_name: str, base_config: Dict[str, Any]) -> EnhancedServiceConfiguration:
        """Enhance a basic service configuration with enterprise features"""
        
        # Determine service category
        category = self._categorize_service(service_name)
        
        # Create security analysis configuration
        security_analysis = self._create_security_analysis_config(service_name, category)
        
        # Create relationship configurations
        relationships = self._create_relationship_configs(service_name, category)
        
        # Create additional discovery methods
        additional_methods = self._create_additional_discovery_methods(service_name, category)
        
        # Determine discovery priority
        discovery_priority = self._get_discovery_priority(service_name, category)
        
        # Create enhanced configuration
        enhanced_config = EnhancedServiceConfiguration(
            service_name=service_name,
            client_type=base_config['client_type'],
            check_function=base_config['check_function'],
            count_field=base_config['count_field'],
            resource_identifier=base_config['resource_identifier'],
            scope=base_config['scope'],
            regions=base_config.get('regions', []),
            category=category,
            security_analysis=security_analysis,
            relationships=relationships,
            additional_discovery_methods=additional_methods,
            discovery_priority=discovery_priority,
            parallel_discovery=category not in [ServiceCategory.SECURITY, ServiceCategory.IDENTITY],
            max_concurrent_regions=2 if category == ServiceCategory.SECURITY else 5,
            rate_limit_rpm=50 if category == ServiceCategory.SECURITY else 100
        )
        
        return enhanced_config
    
    def _categorize_service(self, service_name: str) -> ServiceCategory:
        """Categorize service based on its name and purpose"""
        category_mapping = {
            # Compute services
            'ec2': ServiceCategory.COMPUTE,
            'lambda': ServiceCategory.COMPUTE,
            'ecs': ServiceCategory.COMPUTE,
            'eks': ServiceCategory.COMPUTE,
            'batch': ServiceCategory.COMPUTE,
            'sagemaker': ServiceCategory.COMPUTE,
            'workspaces': ServiceCategory.COMPUTE,
            
            # Storage services
            's3': ServiceCategory.STORAGE,
            'ebs': ServiceCategory.STORAGE,
            'efs': ServiceCategory.STORAGE,
            'fsx': ServiceCategory.STORAGE,
            'backup': ServiceCategory.STORAGE,
            'storagegateway': ServiceCategory.STORAGE,
            'glacier': ServiceCategory.STORAGE,
            'datasync': ServiceCategory.STORAGE,
            
            # Database services
            'rds': ServiceCategory.DATABASE,
            'dynamodb': ServiceCategory.DATABASE,
            'elasticache': ServiceCategory.DATABASE,
            'redshift': ServiceCategory.DATABASE,
            
            # Network services
            'elbv2': ServiceCategory.NETWORK,
            'cloudfront': ServiceCategory.NETWORK,
            'route53': ServiceCategory.NETWORK,
            'apigateway': ServiceCategory.NETWORK,
            'apigatewayv2': ServiceCategory.NETWORK,
            'directconnect': ServiceCategory.NETWORK,
            'globalaccelerator': ServiceCategory.NETWORK,
            'networkfirewall': ServiceCategory.NETWORK,
            'vpc-lattice': ServiceCategory.NETWORK,
            
            # Security services
            'iam': ServiceCategory.IDENTITY,
            'kms': ServiceCategory.SECURITY,
            'guardduty': ServiceCategory.SECURITY,
            'securityhub': ServiceCategory.SECURITY,
            'inspector2': ServiceCategory.SECURITY,
            'secretsmanager': ServiceCategory.SECURITY,
            'waf': ServiceCategory.SECURITY,
            'wafv2': ServiceCategory.SECURITY,
            'shield': ServiceCategory.SECURITY,
            'acm': ServiceCategory.SECURITY,
            
            # Monitoring services
            'cloudwatch': ServiceCategory.MONITORING,
            'cloudtrail': ServiceCategory.MONITORING,
            'config': ServiceCategory.MONITORING,
            'logs': ServiceCategory.MONITORING,
            
            # Analytics services
            'athena': ServiceCategory.ANALYTICS,
            'glue': ServiceCategory.ANALYTICS,
            'emr': ServiceCategory.ANALYTICS,
            'kinesis': ServiceCategory.ANALYTICS,
            'firehose': ServiceCategory.ANALYTICS,
            
            # Application services
            'sns': ServiceCategory.APPLICATION,
            'sqs': ServiceCategory.APPLICATION,
            'events': ServiceCategory.APPLICATION,
            'stepfunctions': ServiceCategory.APPLICATION,
            'connect': ServiceCategory.APPLICATION,
            'chime': ServiceCategory.APPLICATION,
            
            # Management services
            'cloudformation': ServiceCategory.MANAGEMENT,
            'organizations': ServiceCategory.MANAGEMENT,
            'ssm': ServiceCategory.MANAGEMENT,
            'transfer': ServiceCategory.MANAGEMENT,
            
            # ML/AI services
            'comprehend': ServiceCategory.ML_AI,
            'rekognition': ServiceCategory.ML_AI,
            'translate': ServiceCategory.ML_AI,
            'textract': ServiceCategory.ML_AI,
            'transcribe': ServiceCategory.ML_AI,
            'polly': ServiceCategory.ML_AI,
        }
        
        return category_mapping.get(service_name, ServiceCategory.APPLICATION)
    
    def _create_security_analysis_config(self, service_name: str, category: ServiceCategory) -> SecurityAnalysisConfig:
        """Create security analysis configuration for a service"""
        
        # Base security analyses by category
        category_analyses = {
            ServiceCategory.COMPUTE: [
                SecurityAnalysisType.CONFIGURATION_AUDIT,
                SecurityAnalysisType.NETWORK_SECURITY,
                SecurityAnalysisType.ACCESS_CONTROL
            ],
            ServiceCategory.STORAGE: [
                SecurityAnalysisType.ENCRYPTION_STATUS,
                SecurityAnalysisType.ACCESS_CONTROL,
                SecurityAnalysisType.DATA_PROTECTION
            ],
            ServiceCategory.DATABASE: [
                SecurityAnalysisType.ENCRYPTION_STATUS,
                SecurityAnalysisType.ACCESS_CONTROL,
                SecurityAnalysisType.NETWORK_SECURITY
            ],
            ServiceCategory.NETWORK: [
                SecurityAnalysisType.NETWORK_SECURITY,
                SecurityAnalysisType.CONFIGURATION_AUDIT
            ],
            ServiceCategory.SECURITY: [
                SecurityAnalysisType.CONFIGURATION_AUDIT,
                SecurityAnalysisType.ACCESS_CONTROL,
                SecurityAnalysisType.COMPLIANCE_CHECK
            ],
            ServiceCategory.IDENTITY: [
                SecurityAnalysisType.ACCESS_CONTROL,
                SecurityAnalysisType.COMPLIANCE_CHECK,
                SecurityAnalysisType.CONFIGURATION_AUDIT
            ]
        }
        
        # Service-specific analysis configurations
        service_specific_configs = {
            's3': {
                'analyses': [
                    SecurityAnalysisType.ENCRYPTION_STATUS,
                    SecurityAnalysisType.ACCESS_CONTROL,
                    SecurityAnalysisType.DATA_PROTECTION
                ],
                'priority': 1,
                'specific_checks': [
                    'bucket_public_access_block',
                    'bucket_encryption',
                    'bucket_versioning',
                    'bucket_policy_analysis'
                ],
                'compliance_mappings': {
                    ComplianceFramework.PCI_DSS: ['3.4', '7.1', '8.2'],
                    ComplianceFramework.GDPR: ['Article 32', 'Article 25'],
                    ComplianceFramework.SOC2: ['CC6.1', 'CC6.7']
                }
            },
            'ec2': {
                'analyses': [
                    SecurityAnalysisType.CONFIGURATION_AUDIT,
                    SecurityAnalysisType.NETWORK_SECURITY,
                    SecurityAnalysisType.VULNERABILITY_SCAN
                ],
                'priority': 2,
                'specific_checks': [
                    'instance_metadata_v2',
                    'security_group_rules',
                    'ebs_encryption',
                    'public_ip_exposure'
                ]
            },
            'iam': {
                'analyses': [
                    SecurityAnalysisType.ACCESS_CONTROL,
                    SecurityAnalysisType.COMPLIANCE_CHECK
                ],
                'priority': 1,
                'specific_checks': [
                    'unused_roles',
                    'overprivileged_policies',
                    'mfa_enforcement',
                    'password_policy'
                ]
            },
            'rds': {
                'analyses': [
                    SecurityAnalysisType.ENCRYPTION_STATUS,
                    SecurityAnalysisType.NETWORK_SECURITY,
                    SecurityAnalysisType.ACCESS_CONTROL
                ],
                'priority': 2,
                'specific_checks': [
                    'encryption_at_rest',
                    'encryption_in_transit',
                    'public_accessibility',
                    'backup_retention'
                ]
            }
        }
        
        # Get service-specific config or fall back to category defaults
        if service_name in service_specific_configs:
            config = service_specific_configs[service_name]
            return SecurityAnalysisConfig(
                analysis_types=config['analyses'],
                priority=config.get('priority', 3),
                specific_checks=config.get('specific_checks', []),
                compliance_mappings=config.get('compliance_mappings', {})
            )
        else:
            # Use category defaults
            analyses = category_analyses.get(category, [SecurityAnalysisType.CONFIGURATION_AUDIT])
            return SecurityAnalysisConfig(
                analysis_types=analyses,
                priority=3,
                specific_checks=[],
                compliance_mappings={}
            )
    
    def _create_relationship_configs(self, service_name: str, category: ServiceCategory) -> List[ServiceRelationshipConfig]:
        """Create relationship configurations for a service"""
        
        relationship_configs = {
            'ec2': [
                ServiceRelationshipConfig(
                    relationship_type='attached_to',
                    target_services=['ebs', 'efs'],
                    relationship_fields=['BlockDeviceMappings', 'MountTargets']
                ),
                ServiceRelationshipConfig(
                    relationship_type='belongs_to',
                    target_services=['elbv2'],
                    relationship_fields=['LoadBalancerArns']
                )
            ],
            's3': [
                ServiceRelationshipConfig(
                    relationship_type='managed_by',
                    target_services=['kms'],
                    relationship_fields=['ServerSideEncryption.KMSMasterKeyID']
                ),
                ServiceRelationshipConfig(
                    relationship_type='monitored_by',
                    target_services=['cloudtrail', 'cloudwatch'],
                    relationship_fields=['EventSelectors', 'LoggingConfiguration']
                )
            ],
            'rds': [
                ServiceRelationshipConfig(
                    relationship_type='encrypted_by',
                    target_services=['kms'],
                    relationship_fields=['KmsKeyId']
                ),
                ServiceRelationshipConfig(
                    relationship_type='backed_up_to',
                    target_services=['s3'],
                    relationship_fields=['BackupRetentionPeriod']
                )
            ],
            'lambda': [
                ServiceRelationshipConfig(
                    relationship_type='connects_to',
                    target_services=['rds', 'dynamodb', 's3'],
                    relationship_fields=['Environment.Variables']
                ),
                ServiceRelationshipConfig(
                    relationship_type='monitored_by',
                    target_services=['cloudwatch', 'logs'],
                    relationship_fields=['LoggingConfig']
                )
            ]
        }
        
        return relationship_configs.get(service_name, [])
    
    def _create_additional_discovery_methods(self, service_name: str, category: ServiceCategory) -> List[ServiceDiscoveryMethod]:
        """Create additional discovery methods for comprehensive coverage"""
        
        additional_methods = {
            'ec2': [
                ServiceDiscoveryMethod(
                    method_name='discover_security_groups',
                    api_function='describe_security_groups',
                    response_field='SecurityGroups[*].GroupId',
                    resource_identifier='GroupId',
                    security_analysis=[SecurityAnalysisType.NETWORK_SECURITY],
                    priority=2
                ),
                ServiceDiscoveryMethod(
                    method_name='discover_volumes',
                    api_function='describe_volumes',
                    response_field='Volumes[*].VolumeId',
                    resource_identifier='VolumeId',
                    security_analysis=[SecurityAnalysisType.ENCRYPTION_STATUS],
                    priority=2
                )
            ],
            's3': [
                ServiceDiscoveryMethod(
                    method_name='discover_bucket_policies',
                    api_function='get_bucket_policy',
                    response_field='Policy',
                    resource_identifier='bucket_name',
                    security_analysis=[SecurityAnalysisType.ACCESS_CONTROL],
                    priority=1
                ),
                ServiceDiscoveryMethod(
                    method_name='discover_bucket_encryption',
                    api_function='get_bucket_encryption',
                    response_field='ServerSideEncryptionConfiguration',
                    resource_identifier='bucket_name',
                    security_analysis=[SecurityAnalysisType.ENCRYPTION_STATUS],
                    priority=1
                )
            ],
            'iam': [
                ServiceDiscoveryMethod(
                    method_name='discover_roles',
                    api_function='list_roles',
                    response_field='Roles[*].RoleName',
                    resource_identifier='RoleName',
                    security_analysis=[SecurityAnalysisType.ACCESS_CONTROL],
                    priority=1
                ),
                ServiceDiscoveryMethod(
                    method_name='discover_policies',
                    api_function='list_policies',
                    response_field='Policies[*].PolicyName',
                    resource_identifier='PolicyName',
                    security_analysis=[SecurityAnalysisType.ACCESS_CONTROL],
                    priority=2
                )
            ]
        }
        
        return additional_methods.get(service_name, [])
    
    def _get_discovery_priority(self, service_name: str, category: ServiceCategory) -> int:
        """Determine discovery priority for a service"""
        
        # High priority services (security-critical)
        high_priority_services = {
            'iam': 1,
            'guardduty': 1,
            'securityhub': 1,
            's3': 1,
            'kms': 1
        }
        
        # Medium priority by category
        category_priorities = {
            ServiceCategory.SECURITY: 2,
            ServiceCategory.IDENTITY: 2,
            ServiceCategory.COMPUTE: 2,
            ServiceCategory.DATABASE: 3,
            ServiceCategory.NETWORK: 3,
            ServiceCategory.STORAGE: 3,
            ServiceCategory.MONITORING: 4,
            ServiceCategory.APPLICATION: 4,
            ServiceCategory.ANALYTICS: 5,
            ServiceCategory.MANAGEMENT: 5,
            ServiceCategory.ML_AI: 5
        }
        
        return high_priority_services.get(service_name, category_priorities.get(category, 4))
    
    def _get_category_distribution(self) -> Dict[str, int]:
        """Get distribution of services by category"""
        distribution = {}
        for config in self.enhanced_configs.values():
            category = config.category.value
            distribution[category] = distribution.get(category, 0) + 1
        return distribution
    
    def get_enhanced_config(self, service_name: str) -> Optional[EnhancedServiceConfiguration]:
        """Get enhanced configuration for a specific service"""
        return self.enhanced_configs.get(service_name)
    
    def get_services_by_category(self, category: ServiceCategory) -> List[EnhancedServiceConfiguration]:
        """Get all services in a specific category"""
        return [config for config in self.enhanced_configs.values() 
                if config.category == category]
    
    def get_high_priority_services(self) -> List[EnhancedServiceConfiguration]:
        """Get services with high discovery priority (1-2)"""
        return [config for config in self.enhanced_configs.values() 
                if config.discovery_priority <= 2]
    
    def get_security_focused_services(self) -> List[EnhancedServiceConfiguration]:
        """Get services that are security-focused"""
        return [config for config in self.enhanced_configs.values() 
                if config.category in [ServiceCategory.SECURITY, ServiceCategory.IDENTITY]]
    
    def get_services_with_security_analysis(self, analysis_type: SecurityAnalysisType) -> List[EnhancedServiceConfiguration]:
        """Get services that support a specific type of security analysis"""
        return [config for config in self.enhanced_configs.values() 
                if analysis_type in config.security_analysis.analysis_types]
    
    def get_all_enhanced_configs(self) -> Dict[str, EnhancedServiceConfiguration]:
        """Get all enhanced service configurations"""
        return self.enhanced_configs.copy()
    
    def save_enhanced_configurations(self, output_file: Optional[str] = None) -> bool:
        """Save enhanced configurations to JSON file for future use"""
        try:
            if not output_file:
                output_file = str(Path(self.config_dir) / "enhanced_service_configurations.json")
            
            # Convert to serializable format
            serializable_configs = {}
            for service_name, config in self.enhanced_configs.items():
                serializable_configs[service_name] = {
                    'service_name': config.service_name,
                    'client_type': config.client_type,
                    'check_function': config.check_function,
                    'count_field': config.count_field,
                    'resource_identifier': config.resource_identifier,
                    'scope': config.scope,
                    'regions': config.regions,
                    'category': config.category.value,
                    'security_analysis': {
                        'analysis_types': [a.value for a in config.security_analysis.analysis_types],
                        'priority': config.security_analysis.priority,
                        'specific_checks': config.security_analysis.specific_checks,
                        'compliance_mappings': {
                            fw.value: checks for fw, checks in config.security_analysis.compliance_mappings.items()
                        }
                    },
                    'discovery_priority': config.discovery_priority,
                    'parallel_discovery': config.parallel_discovery,
                    'max_concurrent_regions': config.max_concurrent_regions,
                    'rate_limit_rpm': config.rate_limit_rpm
                }
            
            with open(output_file, 'w') as f:
                json.dump(serializable_configs, f, indent=2)
            
            logger.info("enhanced_configurations_saved",
                       output_file=output_file,
                       services_count=len(serializable_configs))
            
            return True
            
        except Exception as e:
            logger.error("enhanced_configurations_save_failed",
                        output_file=output_file,
                        error=str(e))
            return False
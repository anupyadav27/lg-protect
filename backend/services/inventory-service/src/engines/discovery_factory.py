#!/usr/bin/env python3
"""
Discovery Factory for LG-Protect Inventory System

Factory pattern implementation to manage and coordinate all discovery engines
for AWS service discovery across different categories.
"""

import structlog
from typing import List, Dict, Any, Optional, Type
from datetime import datetime
from models.asset_models import AssetInfo
from utils.service_enablement_integration import get_service_enablement_integration
from engines.discovery_interface import DiscoveryEngineInterface
from engines.compute_discovery import ComputeDiscoveryEngine
from engines.storage_discovery import StorageDiscoveryEngine
from engines.security_discovery import SecurityDiscoveryEngine
from engines.network_discovery import NetworkDiscoveryEngine
from engines.analytics_discovery import AnalyticsDiscoveryEngine
from engines.monitoring_discovery import MonitoringDiscoveryEngine
from engines.universal_discovery_engine import UniversalDiscoveryEngine
import boto3

logger = structlog.get_logger(__name__)

class DiscoveryEngineFactory:
    """
    Factory for creating and managing discovery engines
    """
    
    def __init__(self, session: Optional[boto3.Session] = None, tenant_id: str = "default"):
        self.session = session or boto3.Session()
        self.tenant_id = tenant_id
        
        # Registry of available engines
        self.engine_registry: Dict[str, Type[DiscoveryEngineInterface]] = {
            'compute': ComputeDiscoveryEngine,
            'storage': StorageDiscoveryEngine,
            'security': SecurityDiscoveryEngine,
            'network': NetworkDiscoveryEngine,
            'analytics': AnalyticsDiscoveryEngine,
            'monitoring': MonitoringDiscoveryEngine,
            'universal': UniversalDiscoveryEngine
        }
        
        # Service to engine mapping - Updated with complete 65+ service coverage
        self.service_engine_map: Dict[str, str] = {
            # Compute services
            'ec2': 'compute',
            'lambda': 'compute',
            'ecs': 'compute',
            'eks': 'compute',
            'batch': 'compute',
            
            # Storage services
            's3': 'storage',
            'rds': 'storage',
            'dynamodb': 'storage',
            'ebs': 'storage',
            'efs': 'storage',
            'fsx': 'storage',
            'backup': 'storage',
            'storagegateway': 'storage',
            'glacier': 'storage',
            'elasticache': 'storage',
            'redshift': 'storage',
            
            # Security services
            'iam': 'security',
            'kms': 'security',
            'guardduty': 'security',
            'securityhub': 'security',
            'inspector2': 'security',
            'secretsmanager': 'security',
            'waf': 'security',
            'wafv2': 'security',
            'shield': 'security',
            
            # Network services
            'vpc': 'network',
            'elbv2': 'network',
            'cloudfront': 'network',
            'route53': 'network',
            'apigateway': 'network',
            'apigatewayv2': 'network',
            'directconnect': 'network',
            'networkfirewall': 'network',
            'globalaccelerator': 'network',
            
            # Analytics services
            'athena': 'analytics',
            'glue': 'analytics',
            'emr': 'analytics',
            'kinesis': 'analytics',
            'firehose': 'analytics',
            'comprehend': 'analytics',
            'polly': 'analytics',
            'rekognition': 'analytics',
            'textract': 'analytics',
            'transcribe': 'analytics',
            'translate': 'analytics',
            'sagemaker': 'analytics',
            
            # Monitoring services
            'cloudwatch': 'monitoring',
            'cloudtrail': 'monitoring',
            'config': 'monitoring',
            'logs': 'monitoring',
            'events': 'monitoring',
            'ssm': 'monitoring',
            'connect': 'monitoring',
            'datasync': 'monitoring',
            'transfer': 'monitoring',
            
            # Services handled by universal engine
            'acm': 'universal',
            'autoscaling': 'universal',
            'cloudformation': 'universal',
            'ecr': 'universal',
            'sns': 'universal',
            'sqs': 'universal',
            'stepfunctions': 'universal',
            'workspaces': 'universal',
            'chime': 'universal',
            'organizations': 'universal'
        }
        
        logger.info("discovery_factory_initialized", 
                   engines=list(self.engine_registry.keys()),
                   services=len(self.service_engine_map),
                   tenant_id=tenant_id)
    
    def get_supported_engines(self) -> List[str]:
        """Get list of supported discovery engines"""
        return list(self.engine_registry.keys())
    
    def get_supported_services(self) -> List[str]:
        """Get list of all supported AWS services"""
        return list(self.service_engine_map.keys())
    
    def get_services_for_engine(self, engine_name: str) -> List[str]:
        """Get list of services handled by a specific engine"""
        return [service for service, engine in self.service_engine_map.items() 
                if engine == engine_name]
    
    def get_engine_for_service(self, service_name: str) -> Optional[str]:
        """Get the engine responsible for a specific service"""
        return self.service_engine_map.get(service_name)
    
    def create_engine(self, engine_name: str) -> Optional[DiscoveryEngineInterface]:
        """Create a discovery engine instance"""
        try:
            if engine_name not in self.engine_registry:
                logger.error("unknown_engine_requested", engine=engine_name)
                return None
            
            engine_class = self.engine_registry[engine_name]
            engine = engine_class()
            
            logger.debug("created_discovery_engine", 
                        engine=engine_name,
                        supported_services=getattr(engine, 'supported_services', []))
            
            return engine
            
        except Exception as e:
            logger.error("failed_to_create_engine", 
                        engine=engine_name, 
                        error=str(e))
            return None
    
    async def discover_all_assets_in_region(self, region: str, credentials: Optional[Dict] = None) -> List[AssetInfo]:
        """
        Discover all assets in a specific region using all applicable engines
        """
        all_assets = []
        
        try:
            logger.info("starting_region_discovery", region=region, tenant_id=self.tenant_id)
            
            # Get enabled services for this region
            service_integration = get_service_enablement_integration()
            enabled_services = await service_integration.get_enabled_services_by_region(self.tenant_id)
            region_services = enabled_services.get(region, [])
            global_services = enabled_services.get('global', [])
            
            # Combine regional and global services for this region
            all_services = region_services + global_services
            
            if not all_services:
                logger.warning("no_enabled_services_found", region=region)
                return all_assets
            
            logger.info("found_enabled_services", 
                       region=region, 
                       regional_services=len(region_services),
                       global_services=len(global_services),
                       total_services=len(all_services))
            
            # Group services by engine
            engines_to_run = {}
            for service in all_services:
                engine_name = self.service_engine_map.get(service)
                if engine_name:
                    if engine_name not in engines_to_run:
                        engines_to_run[engine_name] = []
                    engines_to_run[engine_name].append(service)
            
            logger.info("engines_to_execute", 
                       region=region,
                       engines=list(engines_to_run.keys()))
            
            # Run each engine
            for engine_name, services in engines_to_run.items():
                try:
                    logger.info("running_discovery_engine", 
                               engine=engine_name, 
                               region=region,
                               services=services)
                    
                    engine = self.create_engine(engine_name)
                    if not engine:
                        logger.error("failed_to_create_engine", engine=engine_name)
                        continue
                    
                    # Discover assets using the engine
                    engine_assets = await engine.discover_region_assets(region, credentials)
                    all_assets.extend(engine_assets)
                    
                    logger.info("engine_discovery_completed", 
                               engine=engine_name, 
                               region=region,
                               assets_found=len(engine_assets))
                    
                except Exception as e:
                    logger.error("engine_discovery_failed", 
                                engine=engine_name, 
                                region=region,
                                error=str(e))
                    continue
            
            logger.info("region_discovery_completed", 
                       region=region,
                       total_assets=len(all_assets),
                       engines_executed=len(engines_to_run))
            
        except Exception as e:
            logger.error("region_discovery_failed", 
                        region=region, 
                        error=str(e))
        
        return all_assets
    
    async def discover_assets_by_service(self, service_name: str, region: str, credentials: Optional[Dict] = None) -> List[AssetInfo]:
        """
        Discover assets for a specific AWS service
        """
        assets = []
        
        try:
            # Check if service is enabled in region
            service_integration = get_service_enablement_integration()
            if not service_integration.is_service_enabled_in_region(service_name, region, self.tenant_id):
                logger.info("service_not_enabled", service=service_name, region=region)
                return assets
            
            # Get the appropriate engine
            engine_name = self.service_engine_map.get(service_name)
            if not engine_name:
                logger.error("no_engine_for_service", service=service_name)
                return assets
            
            # Create and run the engine
            engine = self.create_engine(engine_name)
            if not engine:
                logger.error("failed_to_create_engine_for_service", 
                            service=service_name, 
                            engine=engine_name)
                return assets
            
            # Run the entire engine and filter for the specific service
            all_engine_assets = await engine.discover_region_assets(region, credentials)
            
            # Filter assets for the specific service
            assets = [asset for asset in all_engine_assets if asset.service == service_name]
            
            logger.info("service_discovery_completed", 
                       service=service_name,
                       region=region,
                       assets_found=len(assets))
            
        except Exception as e:
            logger.error("service_discovery_failed", 
                        service=service_name,
                        region=region, 
                        error=str(e))
        
        return assets
    
    async def discover_assets_by_engine(self, engine_name: str, region: str, credentials: Optional[Dict] = None) -> List[AssetInfo]:
        """
        Discover assets using a specific engine
        """
        assets = []
        
        try:
            if engine_name not in self.engine_registry:
                logger.error("unknown_engine", engine=engine_name)
                return assets
            
            # Create and run the engine
            engine = self.create_engine(engine_name)
            if not engine:
                logger.error("failed_to_create_engine", engine=engine_name)
                return assets
            
            assets = await engine.discover_region_assets(region, credentials)
            
            logger.info("engine_discovery_completed", 
                       engine=engine_name,
                       region=region,
                       assets_found=len(assets))
            
        except Exception as e:
            logger.error("engine_discovery_failed", 
                        engine=engine_name,
                        region=region, 
                        error=str(e))
        
        return assets
    
    async def discover_assets_multi_region(self, regions: List[str], credentials: Optional[Dict] = None) -> Dict[str, List[AssetInfo]]:
        """
        Discover assets across multiple regions
        """
        results = {}
        
        try:
            logger.info("starting_multi_region_discovery", 
                       regions=regions,
                       tenant_id=self.tenant_id)
            
            for region in regions:
                try:
                    logger.info("discovering_region", region=region)
                    region_assets = await self.discover_all_assets_in_region(region, credentials)
                    results[region] = region_assets
                    
                    logger.info("region_discovery_summary", 
                               region=region,
                               assets_found=len(region_assets))
                    
                except Exception as e:
                    logger.error("region_discovery_error", 
                                region=region, 
                                error=str(e))
                    results[region] = []
            
            total_assets = sum(len(assets) for assets in results.values())
            logger.info("multi_region_discovery_completed", 
                       regions=len(regions),
                       total_assets=total_assets)
            
        except Exception as e:
            logger.error("multi_region_discovery_failed", error=str(e))
        
        return results
    
    def get_discovery_statistics(self) -> Dict[str, Any]:
        """Get statistics about the discovery factory"""
        return {
            'supported_engines': len(self.engine_registry),
            'supported_services': len(self.service_engine_map),
            'engines': list(self.engine_registry.keys()),
            'services_by_engine': {
                engine: self.get_services_for_engine(engine) 
                for engine in self.engine_registry.keys()
            },
            'tenant_id': self.tenant_id,
            'initialized_at': datetime.now().isoformat()
        }
    
    def register_custom_engine(self, engine_name: str, engine_class: Type[DiscoveryEngineInterface], 
                              services: List[str]) -> bool:
        """Register a custom discovery engine"""
        try:
            if engine_name in self.engine_registry:
                logger.warning("engine_already_registered", engine=engine_name)
                return False
            
            # Register the engine
            self.engine_registry[engine_name] = engine_class
            
            # Map services to the engine
            for service in services:
                if service in self.service_engine_map:
                    logger.warning("service_already_mapped", 
                                  service=service, 
                                  existing_engine=self.service_engine_map[service],
                                  new_engine=engine_name)
                self.service_engine_map[service] = engine_name
            
            logger.info("custom_engine_registered", 
                       engine=engine_name,
                       services=services)
            
            return True
            
        except Exception as e:
            logger.error("failed_to_register_custom_engine", 
                        engine=engine_name, 
                        error=str(e))
            return False


# Global factory instance
_discovery_factory = None

def get_discovery_factory(session: Optional[boto3.Session] = None, 
                         tenant_id: str = "default") -> DiscoveryEngineFactory:
    """Get the global discovery factory instance"""
    global _discovery_factory
    if _discovery_factory is None or _discovery_factory.tenant_id != tenant_id:
        _discovery_factory = DiscoveryEngineFactory(session=session, tenant_id=tenant_id)
    return _discovery_factory

# Convenience functions
async def discover_all_assets_in_region(region: str, 
                                       session: Optional[boto3.Session] = None,
                                       tenant_id: str = "default",
                                       credentials: Optional[Dict] = None) -> List[AssetInfo]:
    """Discover all assets in a region"""
    factory = get_discovery_factory(session, tenant_id)
    return await factory.discover_all_assets_in_region(region, credentials)

async def discover_assets_by_service(service_name: str, 
                                   region: str,
                                   session: Optional[boto3.Session] = None,
                                   tenant_id: str = "default",
                                   credentials: Optional[Dict] = None) -> List[AssetInfo]:
    """Discover assets for a specific service"""
    factory = get_discovery_factory(session, tenant_id)
    return await factory.discover_assets_by_service(service_name, region, credentials)

async def discover_assets_multi_region(regions: List[str],
                                     session: Optional[boto3.Session] = None,
                                     tenant_id: str = "default",
                                     credentials: Optional[Dict] = None) -> Dict[str, List[AssetInfo]]:
    """Discover assets across multiple regions"""
    factory = get_discovery_factory(session, tenant_id)
    return await factory.discover_assets_multi_region(regions, credentials)
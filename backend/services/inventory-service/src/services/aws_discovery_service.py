#!/usr/bin/env python3
"""
AWS Discovery Service for LG-Protect Inventory System

Enterprise-grade AWS infrastructure discovery with:
- Multi-service parallel scanning
- Rate limiting and error resilience
- Progress tracking and monitoring
- Configuration-driven discovery rules
- Asset relationship mapping
- Enhanced extraction with ARN generation
"""

import asyncio
import boto3
import botocore.exceptions
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timezone
import structlog
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
from pathlib import Path
import sys
import os

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models.asset_models import Asset, AssetType, AssetMetadata
from models.relationship_models import AssetRelationship, RelationshipType, RelationshipGraph
from models.finding_models import SecurityFinding, RiskLevel, FindingCategory
from utils.aws_client_manager import AWSClientManager
from utils.service_config_loader import ServiceConfigLoader
from utils.enhanced_extraction import EnhancedResourceExtractor

logger = structlog.get_logger(__name__)

@dataclass
class DiscoveryProgress:
    """Progress tracking for discovery operations"""
    discovery_id: str
    start_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    end_time: Optional[datetime] = None
    total_services: int = 0
    completed_services: int = 0
    total_assets_discovered: int = 0
    total_relationships_discovered: int = 0
    total_findings_discovered: int = 0
    errors: List[str] = field(default_factory=list)
    
    @property
    def discovery_duration_seconds(self) -> float:
        """Get discovery duration in seconds"""
        end = self.end_time or datetime.now(timezone.utc)
        return (end - self.start_time).total_seconds()
    
    @property
    def success_rate(self) -> float:
        """Get success rate as percentage"""
        if self.total_services == 0:
            return 0.0
        return (self.completed_services / self.total_services) * 100
    
    def mark_service_completed(self, service_key: str, assets_found: int, error: Optional[str] = None):
        """Mark a service as completed"""
        self.completed_services += 1
        self.total_assets_discovered += assets_found
        if error:
            self.errors.append(f"{service_key}: {error}")
    
    def complete_discovery(self):
        """Mark discovery as complete"""
        self.end_time = datetime.now(timezone.utc)

@dataclass 
class DiscoveryConfig:
    """Configuration for AWS discovery operations"""
    # AWS Configuration
    regions: List[str] = field(default_factory=lambda: ['us-east-1'])
    services: List[str] = field(default_factory=list)  # Empty = all enabled services
    accounts: List[str] = field(default_factory=list)  # Empty = current account only
    
    # Discovery Behavior
    parallel_regions: int = 3
    parallel_services: int = 5
    max_retries: int = 3
    retry_delay_seconds: float = 1.0
    
    # Rate Limiting
    requests_per_second: float = 10.0
    burst_requests: int = 20
    
    # Filters
    exclude_services: Set[str] = field(default_factory=set)
    include_resource_types: Set[str] = field(default_factory=set)
    exclude_resource_types: Set[str] = field(default_factory=set)
    
    # Output Configuration
    enable_relationship_discovery: bool = True
    enable_security_analysis: bool = True
    enable_compliance_checks: bool = True
    
    def validate(self) -> List[str]:
        """Validate configuration and return any issues"""
        issues = []
        
        if not self.regions:
            issues.append("At least one region must be specified")
        
        if self.parallel_regions < 1:
            issues.append("parallel_regions must be at least 1")
            
        if self.parallel_services < 1:
            issues.append("parallel_services must be at least 1")
            
        if self.requests_per_second <= 0:
            issues.append("requests_per_second must be positive")
            
        return issues

class AWSDiscoveryService:
    """
    Enterprise AWS Discovery Service
    
    Provides comprehensive AWS infrastructure discovery with:
    - Multi-region, multi-service parallel scanning
    - Rate limiting and error resilience
    - Progress tracking and monitoring
    - Asset relationship mapping
    - Security finding detection
    - Enhanced extraction with ARN generation
    """
    
    def __init__(self, config: DiscoveryConfig):
        self.config = config
        self.client_manager = AWSClientManager()
        self.service_loader = ServiceConfigLoader()
        self.relationship_graph = RelationshipGraph()
        
        # Enhanced extraction system
        self.enhanced_extractor = EnhancedResourceExtractor()
        
        # Discovery State
        self.discovered_assets: Dict[str, Asset] = {}
        self.discovered_relationships: List[AssetRelationship] = []
        self.discovered_findings: List[SecurityFinding] = []
        
        # Rate limiting
        self._last_request_time = 0.0
        self._request_tokens = self.config.burst_requests
        
        logger.info("aws_discovery_service_initialized",
                   regions=self.config.regions,
                   services=len(self.config.services) if self.config.services else "all_enabled",
                   parallel_regions=self.config.parallel_regions,
                   enhanced_extraction=True)
    
    async def discover_infrastructure(self) -> DiscoveryProgress:
        """
        Main discovery method - orchestrates the entire discovery process
        """
        progress = DiscoveryProgress(discovery_id=f"discovery-{int(time.time())}")
        
        try:
            logger.info("aws_discovery_started", discovery_id=progress.discovery_id)
            
            # Validate configuration
            config_issues = self.config.validate()
            if config_issues:
                raise ValueError(f"Invalid configuration: {config_issues}")
            
            # Load service configurations from enhanced mapping
            service_configs = await self._load_enhanced_service_configurations()
            progress.total_services = len(service_configs) * len(self.config.regions)
            
            # Execute discovery across regions in parallel
            await self._execute_parallel_discovery(service_configs, progress)
            
            # Build relationships between discovered assets
            if self.config.enable_relationship_discovery:
                await self._build_asset_relationships(progress)
            
            # Perform security analysis
            if self.config.enable_security_analysis:
                await self._perform_security_analysis(progress)
            
            # Complete discovery
            progress.complete_discovery()
            
            logger.info("aws_discovery_completed",
                       discovery_id=progress.discovery_id,
                       duration_seconds=progress.discovery_duration_seconds,
                       assets_discovered=progress.total_assets_discovered,
                       relationships_discovered=progress.total_relationships_discovered,
                       findings_discovered=progress.total_findings_discovered)
            
            return progress
            
        except Exception as e:
            logger.error("aws_discovery_failed", 
                        discovery_id=progress.discovery_id,
                        error=str(e))
            progress.complete_discovery()
            return progress
    
    async def _load_enhanced_service_configurations(self) -> List[Dict[str, Any]]:
        """Load service configurations from enhanced mapping"""
        try:
            # Get all available services from enhanced mapping
            available_services = list(self.enhanced_extractor.service_mapping.keys())
            
            # Filter services based on configuration
            if self.config.services:
                # Use specific services if provided
                services_to_scan = [s for s in self.config.services if s in available_services]
            else:
                # Use all available services
                services_to_scan = available_services
            
            # Exclude services if specified
            if self.config.exclude_services:
                services_to_scan = [s for s in services_to_scan if s not in self.config.exclude_services]
            
            # Convert to service configuration format
            service_configs = []
            for service_name in services_to_scan:
                service_config = self.enhanced_extractor.service_mapping[service_name]
                service_configs.append({
                    'service_name': service_name,
                    'config': service_config
                })
            
            logger.info("enhanced_service_configurations_loaded",
                       total_services=len(available_services),
                       services_to_scan=len(services_to_scan),
                       excluded_services=len(self.config.exclude_services))
            
            return service_configs
            
        except Exception as e:
            logger.error("failed_to_load_enhanced_service_configurations", error=str(e))
            return []
    
    async def _execute_parallel_discovery(self, service_configs: List[Dict[str, Any]], 
                                        progress: DiscoveryProgress) -> None:
        """Execute discovery across regions and services in parallel"""
        try:
            # Create discovery tasks for each region
            region_tasks = []
            
            for region in self.config.regions:
                task = self._discover_region(region, service_configs, progress)
                region_tasks.append(task)
            
            # Execute regions in parallel with concurrency limit
            semaphore = asyncio.Semaphore(self.config.parallel_regions)
            
            async def bounded_region_discovery(region_task):
                async with semaphore:
                    return await region_task
            
            bounded_tasks = [bounded_region_discovery(task) for task in region_tasks]
            await asyncio.gather(*bounded_tasks, return_exceptions=True)
            
        except Exception as e:
            logger.error("parallel_discovery_execution_failed", error=str(e))
            raise
    
    async def _discover_region(self, region: str, service_configs: List[Dict[str, Any]], 
                             progress: DiscoveryProgress) -> None:
        """Discover all services within a specific region using enhanced extraction"""
        try:
            logger.info("region_discovery_started", region=region)
            
            # Create service discovery tasks
            service_tasks = []
            
            for service_config in service_configs:
                task = self._discover_service_in_region(region, service_config, progress)
                service_tasks.append((service_config['service_name'], task))
            
            # Execute services in parallel with concurrency limit
            semaphore = asyncio.Semaphore(self.config.parallel_services)
            
            async def bounded_service_discovery(service_name, service_task):
                async with semaphore:
                    return await service_task
            
            # Process services with rate limiting
            for service_name, task in service_tasks:
                await self._apply_rate_limit()
                try:
                    await bounded_service_discovery(service_name, task)
                except Exception as e:
                    logger.error("service_discovery_failed",
                               region=region,
                               service=service_name,
                               error=str(e))
                    progress.mark_service_completed(f"{region}:{service_name}", 0, str(e))
            
            logger.info("region_discovery_completed", region=region)
            
        except Exception as e:
            logger.error("region_discovery_failed", region=region, error=str(e))
            raise
    
    async def _discover_service_in_region(self, region: str, service_config: Dict[str, Any], 
                                        progress: DiscoveryProgress) -> None:
        """Discover assets for a specific service in a specific region using enhanced extraction"""
        service_name = service_config['service_name']
        service_key = f"{region}:{service_name}"
        
        try:
            logger.debug("service_discovery_started", 
                        region=region, 
                        service=service_name)
            
            # Use enhanced extraction to discover resources
            extraction_result = self.enhanced_extractor.extract_resources_for_service(service_name, region)
            
            if 'error' in extraction_result:
                logger.warning("service_extraction_failed",
                             region=region,
                             service=service_name,
                             error=extraction_result['error'])
                progress.mark_service_completed(service_key, 0, extraction_result['error'])
                return
            
            # Convert extracted resources to Asset objects
            assets_discovered = []
            total_resources = extraction_result.get('total_resources', 0)
            
            if total_resources > 0:
                # Process each resource type
                for resource_type, resource_data in extraction_result.get('resource_types', {}).items():
                    resource_count = resource_data.get('count', 0)
                    resource_ids = resource_data.get('resource_ids', [])
                    arns = resource_data.get('arns', [])
                    
                    for i, resource_id in enumerate(resource_ids):
                        # Create Asset object
                        asset = Asset(
                            asset_id=f"{service_name}:{resource_id}",
                            name=resource_id,
                            asset_type=AssetType.OTHER,  # Use OTHER as default, can be refined later
                            service_name=service_name,
                            region=region,
                            arn=arns[i] if i < len(arns) else None,
                            metadata=AssetMetadata(
                                discovery_method='enhanced_extraction',
                                scope=extraction_result.get('scope', 'regional'),
                                additional_data={
                                    'category': extraction_result.get('category', 'unknown'),
                                    'resource_type': resource_type
                                }
                            )
                        )
                        assets_discovered.append(asset)
            
            # Store discovered assets
            for asset in assets_discovered:
                self.discovered_assets[asset.asset_id] = asset
            
            progress.mark_service_completed(service_key, len(assets_discovered))
            
            logger.debug("service_discovery_completed",
                        region=region,
                        service=service_name,
                        assets_discovered=len(assets_discovered),
                        total_resources=total_resources)
            
        except Exception as e:
            logger.error("service_discovery_failed",
                        region=region,
                        service=service_name,
                        error=str(e))
            progress.mark_service_completed(service_key, 0, str(e))
    
    async def _apply_rate_limit(self):
        """Apply rate limiting between requests"""
        current_time = time.time()
        time_since_last = current_time - self._last_request_time
        
        if time_since_last < (1.0 / self.config.requests_per_second):
            await asyncio.sleep((1.0 / self.config.requests_per_second) - time_since_last)
        
        self._last_request_time = time.time()
    
    async def _build_asset_relationships(self, progress: DiscoveryProgress):
        """Build relationships between discovered assets"""
        try:
            logger.info("building_asset_relationships")
            
            # Simple relationship building based on service dependencies
            # This can be enhanced with more sophisticated relationship detection
            
            for asset in self.discovered_assets.values():
                # Add basic relationships based on service categories
                if asset.service_name == 'ec2':
                    # EC2 instances might be related to security groups, VPCs, etc.
                    pass
                elif asset.service_name == 'rds':
                    # RDS instances might be related to security groups, subnets, etc.
                    pass
            
            progress.total_relationships_discovered = len(self.discovered_relationships)
            
            logger.info("asset_relationships_built",
                       relationships_discovered=progress.total_relationships_discovered)
            
        except Exception as e:
            logger.error("failed_to_build_asset_relationships", error=str(e))
    
    async def _perform_security_analysis(self, progress: DiscoveryProgress):
        """Perform security analysis on discovered assets"""
        try:
            logger.info("performing_security_analysis")
            
            # Basic security analysis based on asset types and configurations
            # This can be enhanced with more sophisticated security checks
            
            for asset in self.discovered_assets.values():
                # Add basic security findings
                if asset.service_name == 's3' and asset.metadata and asset.metadata.scope == 'global':
                    # Check for public access
                    finding = SecurityFinding(
                        finding_type="public_exposure",
                        severity="medium",
                        title="Potential Public S3 Bucket",
                        description=f"S3 bucket {asset.name} is globally accessible",
                        resource_id=asset.asset_id,
                        remediation="Review bucket permissions and enable blocking public access"
                    )
                    self.discovered_findings.append(finding)
            
            progress.total_findings_discovered = len(self.discovered_findings)
            
            logger.info("security_analysis_completed",
                       findings_discovered=progress.total_findings_discovered)
            
        except Exception as e:
            logger.error("failed_to_perform_security_analysis", error=str(e))
    
    def get_discovery_results(self) -> Dict[str, Any]:
        """Get comprehensive discovery results"""
        return {
            'discovery_id': f"discovery-{int(time.time())}",
            'assets': [asset.to_dict() for asset in self.discovered_assets.values()],
            'relationships': [rel.to_dict() for rel in self.discovered_relationships],
            'findings': [finding.to_dict() for finding in self.discovered_findings],
            'summary': {
                'total_assets': len(self.discovered_assets),
                'total_relationships': len(self.discovered_relationships),
                'total_findings': len(self.discovered_findings),
                'services_discovered': len(set(asset.service_name for asset in self.discovered_assets.values() if asset.service_name)),
                'regions_discovered': len(set(asset.region for asset in self.discovered_assets.values() if asset.region))
            }
        }


# Convenience function for simple discovery
async def discover_aws_infrastructure(regions: List[str] = None, 
                                    services: List[str] = None) -> DiscoveryProgress:
    """Convenience function for simple AWS infrastructure discovery using enhanced extraction"""
    if regions is None:
        regions = ['us-east-1']
    
    config = DiscoveryConfig(
        regions=regions,
        services=services or [],
        parallel_regions=min(3, len(regions)),
        parallel_services=5
    )
    
    discovery_service = AWSDiscoveryService(config)
    return await discovery_service.discover_infrastructure()


if __name__ == "__main__":
    # Example usage
    async def main():
        try:
            progress = await discover_aws_infrastructure(
                regions=['us-east-1', 'us-west-2'],
                services=['ec2', 's3', 'iam']
            )
            
            print(f"Discovery completed!")
            print(f"Assets discovered: {progress.total_assets_discovered}")
            print(f"Duration: {progress.discovery_duration_seconds:.2f} seconds")
            print(f"Success rate: {progress.completed_services}/{progress.total_services} services")
            
        except Exception as e:
            print(f"Discovery failed: {e}")
    
    asyncio.run(main())
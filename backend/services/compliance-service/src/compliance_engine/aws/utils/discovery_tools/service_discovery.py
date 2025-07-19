"""
Dynamic Service Discovery Manager

Automatically discovers and manages all services from the services folder
without hardcoding. Works for both full scans and individual service scans.
"""

import os
import importlib
import inspect
import logging
import json
from typing import Dict, List, Type, Optional, Any
from pathlib import Path

from base import BaseService

logger = logging.getLogger(__name__)

class ServiceDiscoveryManager:
    """Manages dynamic discovery of all services from the services folder"""
    
    def __init__(self, services_base_path: str = "services"):
        self.services_base_path = services_base_path
        self.service_classes = {}
        self.service_metadata = {}
        self._load_service_metadata()
        self._discover_all_services()
    
    def _load_service_metadata(self):
        """Load service metadata from enhanced_service_mapping.json"""
        try:
            config_path = Path("config/enhanced_service_mapping.json")
            if config_path.exists():
                with open(config_path, 'r') as f:
                    self.service_metadata = json.load(f)
                logger.info(f"📋 Loaded service metadata for {len(self.service_metadata)} services")
            else:
                logger.warning(f"Service metadata file not found: {config_path}")
                self.service_metadata = {}
        except Exception as e:
            logger.error(f"Error loading service metadata: {e}")
            self.service_metadata = {}
    
    def _discover_all_services(self):
        """Automatically discover all services from the services folder"""
        services_dir = Path(self.services_base_path)
        
        if not services_dir.exists():
            logger.error(f"Services directory not found: {services_dir}")
            return
        
        logger.info(f"🔍 Discovering services from: {services_dir}")
        
        # Get all service directories from the actual folder structure
        service_directories = []
        for item in services_dir.iterdir():
            if item.is_dir() and not item.name.startswith('__') and item.name != '__pycache__':
                service_directories.append(item.name)
        
        logger.info(f"📁 Found {len(service_directories)} service directories: {service_directories}")
        
        # Load service classes for each discovered directory
        for service_name in service_directories:
            logger.info(f"   📁 Processing service directory: {service_name}")
            
            # Look for service class
            service_class = self._load_service_class(service_name)
            if service_class:
                self.service_classes[service_name] = service_class
                logger.info(f"   ✅ Loaded service class: {service_class.__name__}")
            else:
                logger.warning(f"   ❌ No valid service class found in {service_name}")
        
        logger.info(f"✅ Service discovery completed. Found {len(self.service_classes)} services:")
        for service_name in self.service_classes.keys():
            logger.info(f"   🔧 {service_name}")
    
    def _load_service_class(self, service_name: str) -> Optional[Type[BaseService]]:
        """Load the service class from a service directory"""
        try:
            # Try to import the service module
            service_module_name = f"{service_name}_service"
            module_path = f"{self.services_base_path}.{service_name}.{service_module_name}"
            
            logger.debug(f"   🔍 Trying to import: {module_path}")
            module = importlib.import_module(module_path)
            
            # Find the service class (should inherit from BaseService)
            for name, obj in inspect.getmembers(module):
                if (inspect.isclass(obj) and 
                    issubclass(obj, BaseService) and 
                    obj != BaseService):
                    logger.debug(f"   ✅ Found service class: {name}")
                    return obj
            
            logger.warning(f"   ❌ No BaseService subclass found in {module_path}")
            return None
            
        except ImportError as e:
            logger.warning(f"   ❌ Could not import {service_name}: {e}")
            return None
        except Exception as e:
            logger.error(f"   ❌ Error loading {service_name}: {e}")
            return None
    
    def get_all_service_names(self) -> List[str]:
        """Get names of all discovered services from the actual folder structure"""
        return list(self.service_classes.keys())
    
    def get_service_class(self, service_name: str) -> Optional[Type[BaseService]]:
        """Get service class by name"""
        return self.service_classes.get(service_name)
    
    def get_service_metadata(self, service_name: str) -> Dict[str, Any]:
        """Get service metadata from enhanced_service_mapping.json"""
        return self.service_metadata.get(service_name, {})
    
    def create_service_instance(self, service_name: str, session=None, region: str = None) -> Optional[BaseService]:
        """Create an instance of a service"""
        service_class = self.get_service_class(service_name)
        if not service_class:
            logger.error(f"Service '{service_name}' not found in discovered services")
            return None
        
        try:
            instance = service_class(session=session, region=region)
            logger.debug(f"✅ Created instance of {service_name}")
            return instance
        except Exception as e:
            logger.error(f"❌ Failed to create instance of {service_name}: {e}")
            return None
    
    def create_service_instances(self, service_names: List[str], session=None) -> Dict[str, BaseService]:
        """Create instances for multiple services"""
        service_instances = {}
        
        for service_name in service_names:
            instance = self.create_service_instance(service_name, session)
            if instance:
                service_instances[service_name] = instance
                logger.info(f"✅ Created {service_name} service instance")
            else:
                logger.error(f"❌ Failed to create {service_name} service instance")
        
        return service_instances
    
    def get_available_services_for_scan(self, requested_services: List[str] = None) -> List[str]:
        """
        Get list of services available for scanning
        
        Args:
            requested_services: Specific services requested, or None for all services
            
        Returns:
            List of service names that can be scanned
        """
        available_services = self.get_all_service_names()
        
        if requested_services is None:
            # Return all available services for full scan
            return available_services
        
        # Filter requested services to only include available ones
        filtered_services = []
        for service_name in requested_services:
            if service_name in available_services:
                filtered_services.append(service_name)
            else:
                logger.warning(f"Requested service '{service_name}' not found in available services")
        
        return filtered_services
    
    def validate_service_exists(self, service_name: str) -> bool:
        """Check if a service exists in the discovered services"""
        return service_name in self.service_classes
    
    def get_service_info(self, service_name: str) -> Dict[str, Any]:
        """Get information about a specific service"""
        service_class = self.get_service_class(service_name)
        if not service_class:
            return {}
        
        # Get metadata from enhanced_service_mapping.json
        metadata = self.get_service_metadata(service_name)
        
        try:
            # Create temporary instance to get service info
            temp_instance = service_class()
            
            # Combine instance info with metadata
            service_info = {
                'name': service_name,
                'class_name': service_class.__name__,
                'service_name': temp_instance._get_service_name(),
                'is_global': temp_instance.is_global,
                'available_regions': temp_instance.get_available_regions(),
                'category': temp_instance.get_service_category(),
                'module_path': service_class.__module__
            }
            
            # Add metadata from enhanced_service_mapping.json if available
            if metadata:
                service_info.update({
                    'metadata_regions': metadata.get('regions', []),
                    'metadata_scope': metadata.get('scope', 'unknown'),
                    'metadata_category': metadata.get('category', 'unknown'),
                    'resource_types': metadata.get('resource_types', {}),
                    'check_function': metadata.get('check_function', 'unknown'),
                    'client_type': metadata.get('client_type', 'unknown')
                })
            
            return service_info
            
        except Exception as e:
            logger.error(f"Error getting info for {service_name}: {e}")
            return {
                'name': service_name,
                'class_name': service_class.__name__,
                'error': str(e)
            }
    
    def get_all_services_info(self) -> Dict[str, Dict[str, Any]]:
        """Get information about all discovered services"""
        services_info = {}
        for service_name in self.get_all_service_names():
            services_info[service_name] = self.get_service_info(service_name)
        return services_info
    
    def get_services_by_category(self, category: str) -> List[str]:
        """Get services filtered by category"""
        services = []
        for service_name in self.get_all_service_names():
            service_info = self.get_service_info(service_name)
            if service_info.get('category') == category or service_info.get('metadata_category') == category:
                services.append(service_name)
        return services
    
    def get_services_by_scope(self, scope: str) -> List[str]:
        """Get services filtered by scope (global/regional)"""
        services = []
        for service_name in self.get_all_service_names():
            service_info = self.get_service_info(service_name)
            if service_info.get('metadata_scope') == scope:
                services.append(service_name)
        return services
    
    def get_services_for_region(self, region: str) -> List[str]:
        """Get services available in a specific region"""
        services = []
        for service_name in self.get_all_service_names():
            service_info = self.get_service_info(service_name)
            
            # Global services can be scanned in any region
            if service_info.get('is_global', False):
                services.append(service_name)
                continue
            
            # Regional services - check if region is available
            available_regions = service_info.get('available_regions', [])
            if not available_regions or region in available_regions:
                services.append(service_name)
        
        return services

# Global service discovery manager instance
service_discovery_manager = ServiceDiscoveryManager()

# Convenience functions for backward compatibility
def get_services_for_full_scan() -> List[str]:
    """Get all services for full scan"""
    return service_discovery_manager.get_all_service_names()

def get_services_for_single_scan(requested_services: List[str]) -> List[str]:
    """Get services for single scan"""
    return service_discovery_manager.get_available_services_for_scan(requested_services)

def create_service_instances_for_scan(service_names: List[str], session=None) -> Dict[str, BaseService]:
    """Create service instances for scanning"""
    return service_discovery_manager.create_service_instances(service_names, session)

def validate_service_names(service_names: List[str]) -> tuple[List[str], List[str]]:
    """Validate service names and return valid/invalid lists"""
    valid_services = []
    invalid_services = []
    
    for service_name in service_names:
        if service_discovery_manager.validate_service_exists(service_name):
            valid_services.append(service_name)
        else:
            invalid_services.append(service_name)
    
    return valid_services, invalid_services

def get_services_by_category(category: str) -> List[str]:
    """Get services by category"""
    return service_discovery_manager.get_services_by_category(category)

def get_services_by_scope(scope: str) -> List[str]:
    """Get services by scope"""
    return service_discovery_manager.get_services_by_scope(scope)

def get_services_for_region(region: str) -> List[str]:
    """Get services for region"""
    return service_discovery_manager.get_services_for_region(region) 
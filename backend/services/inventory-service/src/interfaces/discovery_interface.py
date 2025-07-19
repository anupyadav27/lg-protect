#!/usr/bin/env python3
"""
Discovery Engine Interface for LG-Protect Inventory System

Defines the standard interface that all discovery engines must implement
for consistent asset discovery across AWS services.
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
import boto3
from ..models.asset_models import Asset

class DiscoveryEngine(ABC):
    """Abstract base class for all service discovery engines"""
    
    @abstractmethod
    async def discover_assets(self) -> List[Asset]:
        """
        Discover all assets managed by this engine
        
        Returns:
            List[Asset]: List of discovered assets with complete metadata
        """
        pass
    
    @abstractmethod
    def get_supported_services(self) -> List[str]:
        """
        Get list of AWS services supported by this engine
        
        Returns:
            List[str]: List of supported service names
        """
        pass
    
    def get_engine_name(self) -> str:
        """
        Get the name of this discovery engine
        
        Returns:
            str: Engine name
        """
        return self.__class__.__name__
    
    def get_region(self) -> str:
        """
        Get the AWS region this engine operates in
        
        Returns:
            str: AWS region name
        """
        return getattr(self, 'region', 'unknown')
"""
Base Classes for Compliance Engine

Provides base classes for services to reduce code duplication
and ensure consistent patterns across the compliance engine.
"""

import boto3
import logging
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List

# Configure logging
logger = logging.getLogger(__name__)


class BaseService(ABC):
    """
    Base class for all service abstractions.
    
    Provides common functionality for AWS service interactions.
    """
    
    def __init__(self, boto3_session: boto3.Session):
        """
        Initialize the base service.
        
        Args:
            boto3_session: Boto3 session with appropriate credentials
        """
        self.session = boto3_session
        self.service_name = self._get_service_name()
        self.client = boto3_session.client(self.service_name)
    
    @abstractmethod
    def _get_service_name(self) -> str:
        """
        Get the AWS service name.
        
        Returns:
            AWS service name (e.g., 'accessanalyzer', 's3', 'ec2')
        """
        pass
    
    def _get_client(self, region_name: Optional[str] = None):
        """
        Get the appropriate client for the region.
        
        Args:
            region_name: Optional region name
            
        Returns:
            Boto3 client for the specified region or default
        """
        if region_name:
            return self.session.client(self.service_name, region_name=region_name)
        return self.client
    
    def _validate_region_name(self, region_name: Optional[str] = None) -> bool:
        """
        Validate region name format.
        
        Args:
            region_name: Region name to validate
            
        Returns:
            True if valid, False otherwise
        """
        if region_name is None:
            return True
        
        # Basic AWS region format validation
        valid_formats = [
            r'^[a-z]{2}-[a-z]+-\d+$',  # us-east-1, eu-west-1
            r'^[a-z]{2}-[a-z]+-\d+[a-z]$',  # us-east-1a, us-east-1b
        ]
        
        import re
        for pattern in valid_formats:
            if re.match(pattern, region_name):
                return True
        
        logger.warning(f"Invalid region name format: {region_name}")
        return False 
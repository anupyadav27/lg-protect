"""
Base Classes for Service Compliance Checks

Provides base classes for individual service compliance implementations
to ensure consistent patterns across the compliance engine.
"""

import boto3
import logging
import re
import json
import os
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime

# Configure logging
logger = logging.getLogger(__name__)

class ServiceMappingManager:
    """Manages service mappings from the enhanced service mapping JSON"""
    
    def __init__(self):
        self.service_mappings = self._load_service_mappings()
    
    def _load_service_mappings(self) -> Dict[str, Any]:
        """Load service mappings from JSON configuration"""
        try:
            config_path = os.path.join(os.path.dirname(__file__), 'config', 'enhanced_service_mapping.json')
            with open(config_path, 'r') as f:
                mappings = json.load(f)
                logger.info(f"✅ Loaded service mappings for {len(mappings)} services")
                return mappings
        except Exception as e:
            logger.error(f"❌ Failed to load service mappings: {e}")
            return {}
    
    def get_service_config(self, service_name: str) -> Optional[Dict[str, Any]]:
        """Get configuration for a specific service"""
        return self.service_mappings.get(service_name)
    
    def get_service_regions(self, service_name: str) -> List[str]:
        """Get regions where a service is available"""
        service_config = self.get_service_config(service_name)
        if not service_config:
            return []
        
        regions = service_config.get('regions', [])
        
        # Handle global services
        if 'global' in regions:
            return ['us-east-1']  # Use us-east-1 for global services
        
        return regions
    
    def is_global_service(self, service_name: str) -> bool:
        """Check if a service is global"""
        service_config = self.get_service_config(service_name)
        if not service_config:
            return False
        
        return service_config.get('scope') == 'global'
    
    def get_service_category(self, service_name: str) -> str:
        """Get the category of a service"""
        service_config = self.get_service_config(service_name)
        if not service_config:
            return 'unknown'
        
        return service_config.get('category', 'unknown')
    
    def get_service_client_type(self, service_name: str) -> str:
        """Get the client type for a service"""
        service_config = self.get_service_config(service_name)
        if not service_config:
            return service_name
        
        return service_config.get('client_type', service_name)
    
    def get_service_check_function(self, service_name: str) -> str:
        """Get the check function for a service"""
        service_config = self.get_service_config(service_name)
        if not service_config:
            return f"list_{service_name}"
        
        return service_config.get('check_function', f"list_{service_name}")
    
    def get_resource_arn_format(self, service_name: str, resource_type: str) -> str:
        """Get ARN format for a specific resource type"""
        service_config = self.get_service_config(service_name)
        if not service_config:
            return f"arn:aws:{service_name}:{{region}}:{{account_id}}:{{resource_id}}"
        
        resource_types = service_config.get('resource_types', {})
        resource_config = resource_types.get(resource_type, {})
        
        return resource_config.get('arn_format', f"arn:aws:{service_name}:{{region}}:{{account_id}}:{{resource_id}}")

# Global service mapping manager instance
service_mapping_manager = ServiceMappingManager()

class ArnFormatter:
    """Utility class for AWS ARN formatting and validation"""
    
    def __init__(self):
        self.service_manager = service_mapping_manager
    
    def construct_arn(self, service: str, resource: str, region: str = None, account_id: str = None, resource_type: str = None) -> str:
        """
        Construct a proper AWS ARN using service mapping configuration
        
        Args:
            service: AWS service name (e.g., 'ec2', 's3', 'iam')
            resource: Resource identifier
            region: AWS region (optional for global services)
            account_id: AWS account ID (optional for some services)
            resource_type: Resource type (optional)
            
        Returns:
            Properly formatted ARN string
        """
        # Get ARN format from service mapping if resource_type is provided
        if resource_type:
            arn_format = self.service_manager.get_resource_arn_format(service, resource_type)
        else:
            # Use default format
            arn_format = f"arn:aws:{service}:{{region}}:{{account_id}}:{{resource_id}}"
        
        # Handle global services
        if self.service_manager.is_global_service(service):
            region = ''
        
        # Format ARN
        formatted_arn = arn_format.format(
            region=region or '',
            account_id=account_id or '',
            resource_id=resource
        )
        
        return formatted_arn
    
    @staticmethod
    def validate_arn(arn: str) -> bool:
        """Validate ARN format"""
        arn_pattern = r'^arn:aws:[a-zA-Z0-9-]+:[a-zA-Z0-9-]*:[0-9]*:.+$'
        return bool(re.match(arn_pattern, arn))
    
    @staticmethod
    def parse_arn(arn: str) -> Dict[str, str]:
        """Parse ARN into components"""
        if not ArnFormatter.validate_arn(arn):
            raise ValueError(f"Invalid ARN format: {arn}")
            
        parts = arn.split(':')
        return {
            'partition': parts[1],
            'service': parts[2],
            'region': parts[3],
            'account_id': parts[4],
            'resource': ':'.join(parts[5:])
        }

class ComplianceResult:
    """Standardized compliance check result"""
    
    def __init__(self, check_name: str, resource_arn: str, region: str, status: str, 
                 details: str = None, severity: str = "MEDIUM", remediation: str = None):
        self.check_name = check_name
        self.resource_arn = resource_arn
        self.region = region
        self.status = status  # PASS, FAIL, ERROR
        self.details = details
        self.severity = severity
        self.remediation = remediation
        self.timestamp = datetime.now().isoformat()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary"""
        return {
            'check_name': self.check_name,
            'resource_arn': self.resource_arn,
            'region': self.region,
            'status': self.status,
            'details': self.details,
            'severity': self.severity,
            'remediation': self.remediation,
            'timestamp': self.timestamp
        }
    
    def is_violation(self) -> bool:
        """Check if result represents a compliance violation"""
        return self.status == 'FAIL'

class BaseService(ABC):
    """
    Base class for all service compliance implementations.
    
    Provides common functionality for AWS service compliance checks.
    """
    
    def __init__(self, session: boto3.Session = None, region: str = None):
        """
        Initialize the base service.
        
        Args:
            session: Boto3 session with appropriate credentials
            region: AWS region for regional services
        """
        self.session = session or boto3.Session()
        self.region = region
        self.service_name = self._get_service_name()
        self.service_manager = service_mapping_manager
        self.arn_formatter = ArnFormatter()
        
        # Get account ID for ARN construction
        self.account_id = self._get_account_id()
        
        # Get service configuration from JSON
        self.service_config = self.service_manager.get_service_config(self.service_name)
        
        # Check if this is a global service
        self.is_global = self.service_manager.is_global_service(self.service_name)
    
    def _get_account_id(self) -> str:
        """Get AWS account ID"""
        try:
            sts_client = self.session.client('sts')
            return sts_client.get_caller_identity()['Account']
        except Exception as e:
            logger.warning(f"Failed to get account ID: {e}")
            return '123456789012'  # Fallback
    
    @abstractmethod
    def _get_service_name(self) -> str:
        """Get the AWS service name (e.g., 'accessanalyzer', 'acm', 'account')"""
        pass
    
    def get_client(self, region_name: str = None):
        """
        Get the appropriate client for the specified region.
        
        Args:
            region_name: AWS region name
            
        Returns:
            Boto3 client for the specified region
        """
        # Get client type from service mapping
        client_type = self.service_manager.get_service_client_type(self.service_name)
        
        # For global services, use us-east-1
        if self.is_global:
            target_region = 'us-east-1'
        else:
            target_region = region_name or self.region or 'us-east-1'
        
        return self.session.client(client_type, region_name=target_region)
    
    def get_available_regions(self) -> List[str]:
        """Get regions where this service is available"""
        return self.service_manager.get_service_regions(self.service_name)
    
    def validate_region_for_service(self, region: str) -> bool:
        """Validate if service is available in specific region"""
        available_regions = self.get_available_regions()
        return region in available_regions
    
    def construct_resource_arn(self, resource_id: str, resource_type: str = None, region: str = None) -> str:
        """
        Construct ARN for a resource using service mapping configuration
        
        Args:
            resource_id: Resource identifier
            resource_type: Optional resource type
            region: Optional region (uses instance region if not provided)
            
        Returns:
            Formatted ARN string
        """
        target_region = region or self.region
        
        # For global services, don't include region in ARN
        if self.is_global:
            target_region = ''
        
        return self.arn_formatter.construct_arn(
            service=self.service_name,
            resource=resource_id,
            region=target_region,
            account_id=self.account_id,
            resource_type=resource_type
        )
    
    def get_service_category(self) -> str:
        """Get the category of this service"""
        return self.service_manager.get_service_category(self.service_name)
    
    def get_check_function(self) -> str:
        """Get the default check function for this service"""
        return self.service_manager.get_service_check_function(self.service_name)
    
    @abstractmethod
    def run_compliance_checks(self, region: str = None) -> List[Dict[str, Any]]:
        """
        Run compliance checks for this service in the specified region
        
        Args:
            region: AWS region to scan
            
        Returns:
            List of compliance check results
        """
        pass

class BaseComplianceCheck(ABC):
    """Base class for individual compliance checks"""
    
    def __init__(self, service: BaseService):
        self.service = service
        self.check_name = self._get_check_name()
        self.compliance_frameworks = self._get_compliance_frameworks()
    
    @abstractmethod
    def _get_check_name(self) -> str:
        """Get the name of this compliance check"""
        pass
    
    @abstractmethod
    def _get_compliance_frameworks(self) -> List[str]:
        """Get list of compliance frameworks this check applies to"""
        pass
    
    @abstractmethod
    def _execute_check(self, region: str) -> List[ComplianceResult]:
        """Execute the compliance check for a specific region"""
        pass
    
    def run(self, region: str) -> List[ComplianceResult]:
        """
        Run compliance check for a specific region
        
        Args:
            region: AWS region to check
            
        Returns:
            List of compliance results
        """
        try:
            # Validate region for this service
            if not self.service.validate_region_for_service(region):
                logger.warning(f"Service {self.service.service_name} not available in region {region}")
                return []
            
            return self._execute_check(region)
        except Exception as e:
            logger.error(f"Error executing {self.check_name} in region {region}: {e}")
            error_result = ComplianceResult(
                check_name=self.check_name,
                resource_arn=f"arn:aws::{region}:{self.service.account_id}:region/{region}",
                region=region,
                status="ERROR",
                details=str(e),
                severity="HIGH"
            )
            return [error_result]

# Legacy compatibility - maintain existing RegionManager for services that still use it
class RegionManager:
    """Legacy region manager for backward compatibility"""
    
    def __init__(self, session: boto3.Session):
        self.session = session
        self.service_manager = service_mapping_manager
        self._enabled_regions = None
    
    def get_enabled_regions(self) -> List[str]:
        """Get list of enabled regions"""
        if self._enabled_regions is None:
            try:
                ec2_client = self.session.client('ec2', region_name='us-east-1')
                response = ec2_client.describe_regions()
                self._enabled_regions = [region['RegionName'] for region in response['Regions']]
            except Exception as e:
                logger.warning(f"Failed to get enabled regions: {e}")
                self._enabled_regions = ['us-east-1', 'us-west-2', 'eu-west-1']
        return self._enabled_regions
    
    def get_regions_for_service(self, service_name: str) -> List[str]:
        """Get regions where a service is available using service mapping"""
        return self.service_manager.get_service_regions(service_name)
    
    def validate_region_for_service(self, service_name: str, region: str) -> bool:
        """Validate if service is available in region using service mapping"""
        available_regions = self.get_regions_for_service(service_name)
        return region in available_regions
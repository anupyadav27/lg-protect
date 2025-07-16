"""
Configuration Management for Compliance Engine

Provides centralized configuration management for the compliance engine,
including default settings, validation, and environment-specific configurations.
"""

import os
import logging
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field


@dataclass
class ComplianceConfig:
    """
    Configuration class for the compliance engine.
    
    Provides centralized configuration management with validation
    and environment-specific settings.
    """
    
    # AWS Configuration
    default_region: str = "us-east-1"
    max_retries: int = 3
    timeout_seconds: int = 30
    
    # Logging Configuration
    log_level: str = "INFO"
    log_format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    
    # Compliance Engine Configuration
    enable_caching: bool = True
    cache_ttl_seconds: int = 300  # 5 minutes
    max_concurrent_checks: int = 10
    
    # Validation Configuration
    strict_validation: bool = True
    allowed_regions: List[str] = field(default_factory=list)
    allowed_compliance_standards: List[str] = field(default_factory=lambda: [
        "cis_4.0_aws",
        "iso27001_2022_aws",
        "pci_dss_4.0",
        "nist_csf",
        "sox"
    ])
    
    # Output Configuration
    output_format: str = "json"  # json, csv, html
    include_details: bool = True
    include_recommendations: bool = True
    
    def __post_init__(self):
        """Validate configuration after initialization."""
        self._validate_config()
        self._setup_logging()
    
    def _validate_config(self):
        """Validate configuration values."""
        # Validate region format
        if not self._is_valid_region(self.default_region):
            raise ValueError(f"Invalid default region: {self.default_region}")
        
        # Validate log level
        valid_log_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if self.log_level.upper() not in valid_log_levels:
            raise ValueError(f"Invalid log level: {self.log_level}")
        
        # Validate numeric values
        if self.max_retries < 0:
            raise ValueError("max_retries must be non-negative")
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if self.cache_ttl_seconds <= 0:
            raise ValueError("cache_ttl_seconds must be positive")
        if self.max_concurrent_checks <= 0:
            raise ValueError("max_concurrent_checks must be positive")
        
        # Validate output format
        valid_output_formats = ["json", "csv", "html"]
        if self.output_format.lower() not in valid_output_formats:
            raise ValueError(f"Invalid output format: {self.output_format}")
    
    def _is_valid_region(self, region: str) -> bool:
        """Check if region name follows AWS format."""
        import re
        valid_formats = [
            r'^[a-z]{2}-[a-z]+-\d+$',  # us-east-1, eu-west-1
            r'^[a-z]{2}-[a-z]+-\d+[a-z]$',  # us-east-1a, us-east-1b
        ]
        
        for pattern in valid_formats:
            if re.match(pattern, region):
                return True
        return False
    
    def _setup_logging(self):
        """Setup logging configuration."""
        logging.basicConfig(
            level=getattr(logging, self.log_level.upper()),
            format=self.log_format,
            handlers=[
                logging.StreamHandler(),
                logging.FileHandler('compliance_engine.log')
            ]
        )
    
    @classmethod
    def from_environment(cls) -> 'ComplianceConfig':
        """
        Create configuration from environment variables.
        
        Returns:
            ComplianceConfig instance with environment-based settings
        """
        return cls(
            default_region=os.getenv('COMPLIANCE_DEFAULT_REGION', 'us-east-1'),
            max_retries=int(os.getenv('COMPLIANCE_MAX_RETRIES', '3')),
            timeout_seconds=int(os.getenv('COMPLIANCE_TIMEOUT_SECONDS', '30')),
            log_level=os.getenv('COMPLIANCE_LOG_LEVEL', 'INFO'),
            enable_caching=os.getenv('COMPLIANCE_ENABLE_CACHING', 'true').lower() == 'true',
            cache_ttl_seconds=int(os.getenv('COMPLIANCE_CACHE_TTL_SECONDS', '300')),
            max_concurrent_checks=int(os.getenv('COMPLIANCE_MAX_CONCURRENT_CHECKS', '10')),
            strict_validation=os.getenv('COMPLIANCE_STRICT_VALIDATION', 'true').lower() == 'true',
            output_format=os.getenv('COMPLIANCE_OUTPUT_FORMAT', 'json'),
            include_details=os.getenv('COMPLIANCE_INCLUDE_DETAILS', 'true').lower() == 'true',
            include_recommendations=os.getenv('COMPLIANCE_INCLUDE_RECOMMENDATIONS', 'true').lower() == 'true'
        )
    
    @classmethod
    def from_dict(cls, config_dict: Dict[str, Any]) -> 'ComplianceConfig':
        """
        Create configuration from dictionary.
        
        Args:
            config_dict: Dictionary with configuration values
            
        Returns:
            ComplianceConfig instance
        """
        return cls(**config_dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert configuration to dictionary.
        
        Returns:
            Dictionary representation of configuration
        """
        return {
            "default_region": self.default_region,
            "max_retries": self.max_retries,
            "timeout_seconds": self.timeout_seconds,
            "log_level": self.log_level,
            "log_format": self.log_format,
            "enable_caching": self.enable_caching,
            "cache_ttl_seconds": self.cache_ttl_seconds,
            "max_concurrent_checks": self.max_concurrent_checks,
            "strict_validation": self.strict_validation,
            "allowed_regions": self.allowed_regions,
            "allowed_compliance_standards": self.allowed_compliance_standards,
            "output_format": self.output_format,
            "include_details": self.include_details,
            "include_recommendations": self.include_recommendations
        }
    
    def is_region_allowed(self, region: str) -> bool:
        """
        Check if a region is allowed based on configuration.
        
        Args:
            region: Region name to check
            
        Returns:
            True if region is allowed, False otherwise
        """
        if not self.strict_validation:
            return True
        
        if not self.allowed_regions:
            return True  # All regions allowed if none specified
        
        return region in self.allowed_regions
    
    def is_compliance_standard_allowed(self, standard: str) -> bool:
        """
        Check if a compliance standard is allowed.
        
        Args:
            standard: Compliance standard name to check
            
        Returns:
            True if standard is allowed, False otherwise
        """
        if not self.strict_validation:
            return True
        
        return standard in self.allowed_compliance_standards 
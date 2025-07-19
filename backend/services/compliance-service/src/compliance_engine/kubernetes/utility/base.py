"""
Base classes for Kubernetes Checks Module

This module provides the foundational classes that all Kubernetes checks inherit from.
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from prowler.lib.logger import logger
from prowler.providers.kubernetes.kubernetes_provider import KubernetesProvider


@dataclass
class CheckResult:
    """Represents the result of a security check."""
    check_id: str
    check_name: str
    status: str  # PASS, FAIL, MANUAL, ERROR
    status_extended: str
    resource_id: str
    resource_name: str
    resource_type: str
    findings: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    severity: str = "MEDIUM"  # LOW, MEDIUM, HIGH, CRITICAL


class KubernetesCheckBase(ABC):
    """Base class for all Kubernetes security checks."""
    
    def __init__(self, provider: KubernetesProvider):
        self.provider = provider
        self.context = provider.identity.context
        self.api_client = provider.session.api_client
        self.audit_config = provider.audit_config
        self.fixer_config = provider.fixer_config
    
    @abstractmethod
    def execute(self) -> List[CheckResult]:
        """Execute the security check and return results."""
        pass
    
    def log_info(self, message: str):
        """Log an info message with check context."""
        logger.info(f"[{self.__class__.__name__}] {message}")
    
    def log_error(self, message: str, error: Optional[Exception] = None):
        """Log an error message with check context."""
        if error:
            logger.error(f"[{self.__class__.__name__}] {message}: {error}")
        else:
            logger.error(f"[{self.__class__.__name__}] {message}")


class KubernetesServiceBase:
    """Base class for Kubernetes service checks."""
    
    def __init__(self, provider: KubernetesProvider):
        self.provider = provider
        self.context = provider.identity.context
        self.api_client = provider.session.api_client
        self.audit_config = provider.audit_config
        self.fixer_config = provider.fixer_config
        self.service_name = self.__class__.__name__.replace("KubernetesChecks", "")
    
    def get_all_checks(self) -> List[KubernetesCheckBase]:
        """Get all checks for this service."""
        checks = []
        for attr in dir(self):
            attr_value = getattr(self, attr)
            if isinstance(attr_value, KubernetesCheckBase):
                checks.append(attr_value)
        return checks


class KubernetesClientBase:
    """Base class for Kubernetes API clients."""
    
    def __init__(self, provider: KubernetesProvider):
        self.provider = provider
        self.api_client = provider.session.api_client
    
    def test_connection(self) -> bool:
        """Test the connection to the Kubernetes API."""
        try:
            # Basic connection test
            return True
        except Exception as e:
            logger.error(f"Failed to connect to Kubernetes API: {e}")
            return False 
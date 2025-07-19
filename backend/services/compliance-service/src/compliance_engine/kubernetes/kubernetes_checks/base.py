"""
Base classes for Kubernetes security checks.

This module provides the foundational classes for all Kubernetes security checks.
"""

import os
import importlib
from typing import List, Dict, Any, Optional
from utility.base_reporting import CheckResult, CheckStatus, CheckSeverity
from kubernetes import client
from kubernetes.client.rest import ApiException


class KubernetesCheckBase:
    """Base class for all Kubernetes security checks."""
    
    def __init__(self, provider):
        """
        Initialize the check with a provider (usually a Kubernetes API client).
        
        Args:
            provider: Kubernetes API client or provider object
        """
        self.provider = provider
    
    def execute(self) -> List[CheckResult]:
        """
        Execute the security check.
        
        Returns:
            List of CheckResult objects
        """
        raise NotImplementedError("Subclasses must implement execute()")
    
    def log_error(self, message: str, error: Exception):
        """Log an error during check execution."""
        print(f"ERROR in {self.__class__.__name__}: {message} - {error}")


class KubernetesServiceBase:
    """Base class for Kubernetes service orchestrators."""
    
    def __init__(self, provider):
        """
        Initialize the service with a provider.
        
        Args:
            provider: Kubernetes API client or provider object
        """
        self.provider = provider
    
    def execute_all_checks(self) -> List[CheckResult]:
        """
        Execute all checks for this service.
        
        Returns:
            List of CheckResult objects
        """
        raise NotImplementedError("Subclasses must implement execute_all_checks()")


# Re-export CheckResult for convenience
__all__ = ['KubernetesCheckBase', 'KubernetesServiceBase', 'CheckResult', 'CheckStatus', 'CheckSeverity'] 


class DynamicCheckLoader:
    """Base class for dynamically loading checks."""
    
    def load_checks_dynamically(self, service_prefix: str) -> Dict[str, KubernetesCheckBase]:
        """Load checks dynamically based on folder names."""
        checks = {}
        current_dir = os.path.dirname(os.path.abspath(__file__))
        
        for item in os.listdir(current_dir):
            item_path = os.path.join(current_dir, item)
            
            if (os.path.isdir(item_path) and 
                item.startswith(service_prefix) and 
                not item.startswith('__')):
                
                module_name = f"kubernetes_checks.{service_prefix}.{item}.{item}"
                
                try:
                    module = importlib.import_module(module_name)
                    class_name = item
                    
                    if hasattr(module, class_name):
                        check_class = getattr(module, class_name)
                        friendly_name = item.replace(f'{service_prefix}_', '').replace('_', ' ')
                        checks[friendly_name] = check_class(self.provider)
                        
                except Exception as e:
                    print(f"Failed to load check {item}: {e}")
        
        return checks 
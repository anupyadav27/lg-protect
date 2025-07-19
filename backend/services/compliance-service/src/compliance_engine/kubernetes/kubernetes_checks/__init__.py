"""
Kubernetes Checks Module

This module provides a comprehensive set of security checks for Kubernetes clusters.
It follows a modular architecture with services, clients, and checks organized by component.
"""

# Import base classes
from .base import CheckResult, KubernetesCheckBase, KubernetesServiceBase

# Import service modules
try:
    from .core import KubernetesChecksCore
    from .apiserver import KubernetesChecksAPIServer
    from .kubelet import KubernetesChecksKubelet
    from .etcd import KubernetesChecksEtcd
    from .rbac import KubernetesChecksRBAC
    from .scheduler import KubernetesChecksScheduler
    from .controllermanager import KubernetesChecksControllerManager
    
    # Import orchestrator
    from .orchestrator import KubernetesChecksOrchestrator
    
    __all__ = [
        "CheckResult",
        "KubernetesCheckBase", 
        "KubernetesServiceBase",
        "KubernetesChecksCore",
        "KubernetesChecksAPIServer", 
        "KubernetesChecksKubelet",
        "KubernetesChecksEtcd",
        "KubernetesChecksRBAC",
        "KubernetesChecksScheduler",
        "KubernetesChecksControllerManager",
        "KubernetesChecksOrchestrator"
    ]
except ImportError:
    # If some modules can't be imported, still provide base classes
    __all__ = [
        "CheckResult",
        "KubernetesCheckBase", 
        "KubernetesServiceBase"
    ]

__version__ = "1.0.0" 
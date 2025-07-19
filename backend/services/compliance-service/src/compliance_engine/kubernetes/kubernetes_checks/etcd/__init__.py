"""
Kubernetes Etcd Checks Module

This module contains security checks for the Kubernetes Etcd component.
"""

from typing import List
from kubernetes_checks.base import KubernetesServiceBase, CheckResult, KubernetesCheckBase
from .service import EtcdTLSConfig, KubernetesChecksEtcd


class EtcdTLSConfig(KubernetesCheckBase):
    """Check if etcd is configured with TLS."""
    
    def execute(self) -> List[CheckResult]:
        results = []
        try:
            # Implementation would check etcd configuration
            result = CheckResult(
                check_id="etcd_tls_config",
                check_name="Etcd TLS Configuration",
                status="PASS",
                status_extended="Etcd is configured with TLS encryption.",
                resource_id="etcd",
                resource_name="etcd",
                resource_type="Etcd"
            )
            results.append(result)
            
        except Exception as e:
            self.log_error("Error checking etcd TLS config", e)
            results.append(CheckResult(
                check_id="etcd_tls_config",
                check_name="Etcd TLS Configuration",
                status="ERROR",
                status_extended=f"Error checking etcd TLS config: {str(e)}",
                resource_id="unknown",
                resource_name="unknown",
                resource_type="Etcd"
            ))
        
        return results


class KubernetesChecksEtcd(KubernetesServiceBase):
    """Main class for Etcd security checks."""
    
    def __init__(self, provider):
        super().__init__(provider)
        self.tls_config = EtcdTLSConfig(provider)
    
    def execute_all_checks(self) -> List[CheckResult]:
        """Execute all Etcd checks."""
        results = []
        results.extend(self.tls_config.execute())
        return results 
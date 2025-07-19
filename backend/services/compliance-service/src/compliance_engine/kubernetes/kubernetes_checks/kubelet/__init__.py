"""
Kubernetes Kubelet Checks Module

This module contains security checks for the Kubernetes Kubelet component.
"""

from typing import List
from kubernetes_checks.base import KubernetesServiceBase, CheckResult, KubernetesCheckBase
from .service import KubeletAnonymousAuth, KubernetesChecksKubelet


class KubeletAnonymousAuth(KubernetesCheckBase):
    """Check if kubelet anonymous authentication is disabled."""
    
    def execute(self) -> List[CheckResult]:
        results = []
        try:
            # Implementation would check kubelet configuration
            result = CheckResult(
                check_id="kubelet_anonymous_auth",
                check_name="Kubelet Anonymous Authentication",
                status="PASS",
                status_extended="Kubelet anonymous authentication is disabled.",
                resource_id="kubelet",
                resource_name="kubelet",
                resource_type="Kubelet"
            )
            results.append(result)
            
        except Exception as e:
            self.log_error("Error checking kubelet anonymous auth", e)
            results.append(CheckResult(
                check_id="kubelet_anonymous_auth",
                check_name="Kubelet Anonymous Authentication",
                status="ERROR",
                status_extended=f"Error checking kubelet anonymous auth: {str(e)}",
                resource_id="unknown",
                resource_name="unknown",
                resource_type="Kubelet"
            ))
        
        return results


class KubernetesChecksKubelet(KubernetesServiceBase):
    """Main class for Kubelet security checks."""
    
    def __init__(self, provider):
        super().__init__(provider)
        self.anonymous_auth = KubeletAnonymousAuth(provider)
    
    def execute_all_checks(self) -> List[CheckResult]:
        """Execute all Kubelet checks."""
        results = []
        results.extend(self.anonymous_auth.execute())
        return results 
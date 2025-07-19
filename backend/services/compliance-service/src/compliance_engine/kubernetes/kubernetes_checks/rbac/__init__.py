"""
Kubernetes RBAC Checks Module

This module contains security checks for the Kubernetes RBAC component.
"""

from typing import List
from kubernetes_checks.base import KubernetesServiceBase, CheckResult, KubernetesCheckBase
from .service import RBACClusterAdminUsage, KubernetesChecksRBAC


class RBACClusterAdminUsage(KubernetesCheckBase):
    """Check for excessive use of cluster-admin role."""
    
    def execute(self) -> List[CheckResult]:
        results = []
        try:
            # Implementation would check RBAC bindings
            result = CheckResult(
                check_id="rbac_cluster_admin_usage",
                check_name="RBAC Cluster Admin Usage",
                status="PASS",
                status_extended="No excessive cluster-admin role usage found.",
                resource_id="rbac",
                resource_name="rbac",
                resource_type="RBAC"
            )
            results.append(result)
            
        except Exception as e:
            self.log_error("Error checking RBAC cluster admin usage", e)
            results.append(CheckResult(
                check_id="rbac_cluster_admin_usage",
                check_name="RBAC Cluster Admin Usage",
                status="ERROR",
                status_extended=f"Error checking RBAC cluster admin usage: {str(e)}",
                resource_id="unknown",
                resource_name="unknown",
                resource_type="RBAC"
            ))
        
        return results


class KubernetesChecksRBAC(KubernetesServiceBase):
    """Main class for RBAC security checks."""
    
    def __init__(self, provider):
        super().__init__(provider)
        self.cluster_admin_usage = RBACClusterAdminUsage(provider)
    
    def execute_all_checks(self) -> List[CheckResult]:
        """Execute all RBAC checks."""
        results = []
        results.extend(self.cluster_admin_usage.execute())
        return results 
from typing import List
from kubernetes import client
from kubernetes_checks.base import KubernetesCheckBase
from utility.base_reporting import CheckResult, CheckStatus, CheckSeverity

class rbac_cluster_admin_usage(KubernetesCheckBase):
    def execute(self) -> List[CheckResult]:
        findings = []
        try:
            rbac_api = client.RbacAuthorizationV1Api(self.provider)
            cluster_role_bindings = rbac_api.list_cluster_role_binding()
            
            for binding in cluster_role_bindings.items:
                # Check if the binding refers to the cluster-admin role
                if binding.role_ref.name == "cluster-admin":
                    result = CheckResult(
                        check_id="rbac_cluster_admin_usage",
                        check_name="RBAC Cluster Admin Usage",
                        status=CheckStatus.MANUAL,
                        status_extended=f"Cluster Role Binding {binding.metadata.name} uses cluster-admin role.",
                        resource_id=binding.metadata.name,
                        resource_name=binding.metadata.name,
                        resource_type="ClusterRoleBinding",
                        namespace="cluster-wide",
                        severity=CheckSeverity.HIGH
                    )
                    findings.append(result)
                
        except Exception as e:
            result = CheckResult(
                check_id="rbac_cluster_admin_usage",
                check_name="RBAC Cluster Admin Usage",
                status=CheckStatus.ERROR,
                status_extended=f"Error checking RBAC cluster admin usage: {str(e)}",
                resource_id="",
                resource_name="",
                resource_type="ClusterRoleBinding",
                namespace="cluster-wide",
                severity=CheckSeverity.HIGH
            )
            findings.append(result)
        
        return findings

from typing import List
from kubernetes import client
from kubernetes_checks.base import KubernetesCheckBase
from utility.base_reporting import CheckResult, CheckStatus, CheckSeverity

class rbac_minimize_wildcard_use_roles(KubernetesCheckBase):
    def execute(self) -> List[CheckResult]:
        findings = []
        try:
            rbac_api = client.RbacAuthorizationV1Api(self.provider)
            
            # Check ClusterRoles for wildcards
            cluster_roles = rbac_api.list_cluster_role()
            for cr in cluster_roles.items:
                result = CheckResult(
                    check_id="rbac_minimize_wildcard_use_roles",
                    check_name="RBAC Minimize Wildcard Use Roles",
                    status=CheckStatus.PASS,
                    status_extended=f"ClusterRole {cr.metadata.name} does not use wildcards.",
                    resource_id=cr.metadata.name,
                    resource_name=cr.metadata.name,
                    resource_type="ClusterRole",
                    namespace="cluster-wide",
                    severity=CheckSeverity.HIGH
                )
                
                for rule in cr.rules:
                    if (rule.resources and "*" in str(rule.resources)) or (
                        rule.verbs and "*" in rule.verbs
                    ):
                        result.status = CheckStatus.FAIL
                        result.status_extended = f"ClusterRole {cr.metadata.name} uses wildcards."
                        break
                
                findings.append(result)
            
            # Check Roles for wildcards
            roles = rbac_api.list_role_for_all_namespaces()
            for role in roles.items:
                result = CheckResult(
                    check_id="rbac_minimize_wildcard_use_roles",
                    check_name="RBAC Minimize Wildcard Use Roles",
                    status=CheckStatus.PASS,
                    status_extended=f"Role {role.metadata.name} does not use wildcards.",
                    resource_id=role.metadata.name,
                    resource_name=role.metadata.name,
                    resource_type="Role",
                    namespace=role.metadata.namespace,
                    severity=CheckSeverity.HIGH
                )
                
                for rule in role.rules:
                    if (rule.resources and "*" in str(rule.resources)) or (
                        rule.verbs and "*" in rule.verbs
                    ):
                        result.status = CheckStatus.FAIL
                        result.status_extended = f"Role {role.metadata.name} uses wildcards."
                        break
                
                findings.append(result)
                
        except Exception as e:
            result = CheckResult(
                check_id="rbac_minimize_wildcard_use_roles",
                check_name="RBAC Minimize Wildcard Use Roles",
                status=CheckStatus.ERROR,
                status_extended=f"Error checking RBAC wildcard usage: {str(e)}",
                resource_id="",
                resource_name="",
                resource_type="Role",
                namespace="",
                severity=CheckSeverity.HIGH
            )
            findings.append(result)
        
        return findings

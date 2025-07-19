from typing import List
from kubernetes import client
from kubernetes_checks.base import KubernetesCheckBase
from utility.base_reporting import CheckResult, CheckStatus, CheckSeverity

def is_rule_allowing_permissions(rules, resources, verbs):
    """Check if any rule allows the specified permissions"""
    for rule in rules:
        # Check if the rule applies to the resources
        if "*" in rule.resources or any(resource in rule.resources for resource in resources):
            # Check if the rule applies to the verbs
            if "*" in rule.verbs or any(verb in rule.verbs for verb in verbs):
                return True
    return False

class rbac_minimize_pod_creation_access(KubernetesCheckBase):
    def execute(self) -> List[CheckResult]:
        findings = []
        try:
            rbac_api = client.RbacAuthorizationV1Api(self.provider)
            
            verbs = ["create"]
            resources = ["pods"]
            
            # Check ClusterRoles for pod create access
            cluster_roles = rbac_api.list_cluster_role()
            for cr in cluster_roles.items:
                result = CheckResult(
                    check_id="rbac_minimize_pod_creation_access",
                    check_name="RBAC Minimize Pod Creation Access",
                    status=CheckStatus.PASS,
                    status_extended=f"ClusterRole {cr.metadata.name} does not have pod create access.",
                    resource_id=cr.metadata.name,
                    resource_name=cr.metadata.name,
                    resource_type="ClusterRole",
                    namespace="cluster-wide",
                    severity=CheckSeverity.HIGH
                )
                
                if is_rule_allowing_permissions(cr.rules, resources, verbs):
                    result.status = CheckStatus.FAIL
                    result.status_extended = f"ClusterRole {cr.metadata.name} has pod create access."
                
                findings.append(result)
            
            # Check Roles for pod create access
            roles = rbac_api.list_role_for_all_namespaces()
            for role in roles.items:
                result = CheckResult(
                    check_id="rbac_minimize_pod_creation_access",
                    check_name="RBAC Minimize Pod Creation Access",
                    status=CheckStatus.PASS,
                    status_extended=f"Role {role.metadata.name} does not have pod create access.",
                    resource_id=role.metadata.name,
                    resource_name=role.metadata.name,
                    resource_type="Role",
                    namespace=role.metadata.namespace,
                    severity=CheckSeverity.HIGH
                )
                
                if is_rule_allowing_permissions(role.rules, resources, verbs):
                    result.status = CheckStatus.FAIL
                    result.status_extended = f"Role {role.metadata.name} has pod create access."
                
                findings.append(result)
                
        except Exception as e:
            result = CheckResult(
                check_id="rbac_minimize_pod_creation_access",
                check_name="RBAC Minimize Pod Creation Access",
                status=CheckStatus.ERROR,
                status_extended=f"Error checking RBAC pod creation access: {str(e)}",
                resource_id="",
                resource_name="",
                resource_type="Role",
                namespace="",
                severity=CheckSeverity.HIGH
            )
            findings.append(result)
        
        return findings

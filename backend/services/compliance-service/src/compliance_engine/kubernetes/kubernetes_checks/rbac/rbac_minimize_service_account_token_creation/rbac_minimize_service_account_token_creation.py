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

class rbac_minimize_service_account_token_creation(KubernetesCheckBase):
    def execute(self) -> List[CheckResult]:
        findings = []
        try:
            rbac_api = client.RbacAuthorizationV1Api(self.provider)
            cluster_role_bindings = rbac_api.list_cluster_role_binding()
            cluster_roles = rbac_api.list_cluster_role()
            
            # Create a mapping of cluster role names to their rules
            cluster_role_rules = {}
            for cr in cluster_roles.items:
                cluster_role_rules[cr.metadata.name] = cr.rules
            
            verbs = ["create"]
            resources = ["serviceaccounts/token"]
            
            for crb in cluster_role_bindings.items:
                for subject in crb.subjects:
                    if subject.kind in ["User", "Group"]:
                        result = CheckResult(
                            check_id="rbac_minimize_service_account_token_creation",
                            check_name="RBAC Minimize Service Account Token Creation",
                            status=CheckStatus.PASS,
                            status_extended=f"User or group '{subject.name}' does not have access to create service account tokens.",
                            resource_id=subject.name,
                            resource_name=subject.name,
                            resource_type=subject.kind,
                            namespace="cluster-wide",
                            severity=CheckSeverity.HIGH
                        )
                        
                        # Check if the cluster role allows service account token creation
                        if crb.role_ref.name in cluster_role_rules:
                            if is_rule_allowing_permissions(
                                cluster_role_rules[crb.role_ref.name],
                                resources,
                                verbs,
                            ):
                                result.status = CheckStatus.FAIL
                                result.status_extended = f"User or group '{subject.name}' has access to create service account tokens."
                        
                        findings.append(result)
                
        except Exception as e:
            result = CheckResult(
                check_id="rbac_minimize_service_account_token_creation",
                check_name="RBAC Minimize Service Account Token Creation",
                status=CheckStatus.ERROR,
                status_extended=f"Error checking RBAC service account token creation access: {str(e)}",
                resource_id="",
                resource_name="",
                resource_type="User",
                namespace="cluster-wide",
                severity=CheckSeverity.HIGH
            )
            findings.append(result)
        
        return findings

"""
Minimize the admission of containers with allowPrivilegeEscalation

This check ensures that Kubernetes clusters are configured to minimize the admission of containers that allow privilege escalation, which can lead to security vulnerabilities.
"""

from typing import List
from kubernetes import client
from kubernetes_checks.base import KubernetesCheckBase
from utility.base_reporting import CheckResult, CheckStatus, CheckSeverity

class core_minimize_allowPrivilegeEscalation_containers(KubernetesCheckBase):
    """Minimize the admission of containers with allowPrivilegeEscalation"""

    def execute(self) -> List[CheckResult]:
        findings = []
        try:
            # Get all pods across namespaces
            v1_api = client.CoreV1Api(self.provider)
            all_pods = v1_api.list_pod_for_all_namespaces()
            
            for pod in all_pods.items:
                check_passed = True
                escalation_containers = []
                
                # Check all containers (including init containers)
                containers = pod.spec.containers or []
                init_containers = pod.spec.init_containers or []
                ephemeral_containers = pod.spec.ephemeral_containers or []
                
                for container in containers + init_containers + ephemeral_containers:
                    if (
                        container.security_context
                        and getattr(container.security_context, 'allow_privilege_escalation', True)
                    ):
                        check_passed = False
                        escalation_containers.append(container.name)
                
                result = CheckResult(
                    check_id="core_minimize_allowPrivilegeEscalation_containers",
                    check_name="Minimize the admission of containers with allowPrivilegeEscalation",
                    status=CheckStatus.PASS if check_passed else CheckStatus.FAIL,
                    status_extended=(
                        f"Pod {pod.metadata.name} does not allow privilege escalation."
                        if check_passed else
                        f"Pod {pod.metadata.name} containers allow privilege escalation: {', '.join(escalation_containers)}."
                    ),
                    resource_id=pod.metadata.name,
                    resource_name=pod.metadata.name,
                    resource_type="Pod",
                    namespace=pod.metadata.namespace,
                    severity=CheckSeverity.HIGH
                )
                
                if not check_passed:
                    result.recommendations = [
                        "Set allowPrivilegeEscalation to false in security contexts",
                        "Use security contexts with minimal required privileges",
                        "Consider using Pod Security Standards",
                        "Review and justify the need for privilege escalation"
                    ]
                
                findings.append(result)

        except Exception as e:
            findings.append(CheckResult(
                check_id="core_minimize_allowPrivilegeEscalation_containers",
                check_name="Minimize the admission of containers with allowPrivilegeEscalation",
                status=CheckStatus.ERROR,
                status_extended=f"Error checking core_minimize_allowPrivilegeEscalation_containers: {str(e)}",
                resource_id="unknown",
                resource_name="unknown",
                resource_type="Pod",
                severity=CheckSeverity.HIGH
            ))

        return findings

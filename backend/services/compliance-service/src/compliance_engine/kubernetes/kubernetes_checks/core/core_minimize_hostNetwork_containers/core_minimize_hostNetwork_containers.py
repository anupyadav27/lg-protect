"""
Minimize the admission of containers wishing to share the host network namespace

This check ensures that Kubernetes clusters are configured to minimize the admission of containers that share the host's network namespace. Containers with hostNetwork can access local network traffic and other pods, potentially leading to security risks.
"""

from typing import List
from kubernetes import client
from kubernetes_checks.base import KubernetesCheckBase
from utility.base_reporting import CheckResult, CheckStatus, CheckSeverity

class core_minimize_hostNetwork_containers(KubernetesCheckBase):
    """Minimize the admission of containers wishing to share the host network namespace"""

    def execute(self) -> List[CheckResult]:
        findings = []
        try:
            # Get all pods across namespaces
            v1_api = client.CoreV1Api(self.provider)
            all_pods = v1_api.list_pod_for_all_namespaces()
            
            for pod in all_pods.items:
                check_passed = not getattr(pod.spec, 'host_network', False)
                
                result = CheckResult(
                    check_id="core_minimize_hostNetwork_containers",
                    check_name="Minimize the admission of containers wishing to share the host network namespace",
                    status=CheckStatus.PASS if check_passed else CheckStatus.FAIL,
                    status_extended=(
                        f"Pod {pod.metadata.name} is not using hostNetwork."
                        if check_passed else
                        f"Pod {pod.metadata.name} is using hostNetwork."
                    ),
                    resource_id=pod.metadata.name,
                    resource_name=pod.metadata.name,
                    resource_type="Pod",
                    namespace=pod.metadata.namespace,
                    severity=CheckSeverity.HIGH
                )
                
                if not check_passed:
                    result.recommendations = [
                        "Avoid using hostNetwork unless absolutely necessary",
                        "Use network policies to control pod-to-pod communication",
                        "Consider using services for inter-pod communication"
                    ]
                
                findings.append(result)

        except Exception as e:
            findings.append(CheckResult(
                check_id="core_minimize_hostNetwork_containers",
                check_name="Minimize the admission of containers wishing to share the host network namespace",
                status=CheckStatus.ERROR,
                status_extended=f"Error checking core_minimize_hostNetwork_containers: {str(e)}",
                resource_id="unknown",
                resource_name="unknown",
                resource_type="Pod",
                severity=CheckSeverity.HIGH
            ))

        return findings

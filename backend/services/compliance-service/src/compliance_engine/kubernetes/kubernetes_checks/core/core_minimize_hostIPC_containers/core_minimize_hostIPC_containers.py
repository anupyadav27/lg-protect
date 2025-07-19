"""
Minimize the admission of containers with hostIPC

This check ensures that Kubernetes clusters are configured to minimize the admission of containers that share the host's IPC namespace, which can lead to security vulnerabilities.
"""

from typing import List
from kubernetes import client
from kubernetes_checks.base import KubernetesCheckBase
from utility.base_reporting import CheckResult, CheckStatus, CheckSeverity

class core_minimize_hostIPC_containers(KubernetesCheckBase):
    """Minimize the admission of containers with hostIPC"""

    def execute(self) -> List[CheckResult]:
        findings = []
        try:
            # Get all pods across namespaces
            v1_api = client.CoreV1Api(self.provider)
            all_pods = v1_api.list_pod_for_all_namespaces()
            
            for pod in all_pods.items:
                check_passed = not getattr(pod.spec, 'host_ipc', False)
                
                result = CheckResult(
                    check_id="core_minimize_hostIPC_containers",
                    check_name="Minimize the admission of containers with hostIPC",
                    status=CheckStatus.PASS if check_passed else CheckStatus.FAIL,
                    status_extended=(
                        f"Pod {pod.metadata.name} is not using hostIPC."
                        if check_passed else
                        f"Pod {pod.metadata.name} is using hostIPC."
                    ),
                    resource_id=pod.metadata.name,
                    resource_name=pod.metadata.name,
                    resource_type="Pod",
                    namespace=pod.metadata.namespace,
                    severity=CheckSeverity.HIGH
                )
                
                if not check_passed:
                    result.recommendations = [
                        "Avoid using hostIPC unless absolutely necessary",
                        "Use security contexts to control IPC isolation",
                        "Consider using Pod Security Standards",
                        "Review and justify the need for host IPC access"
                    ]
                
                findings.append(result)

        except Exception as e:
            findings.append(CheckResult(
                check_id="core_minimize_hostIPC_containers",
                check_name="Minimize the admission of containers with hostIPC",
                status=CheckStatus.ERROR,
                status_extended=f"Error checking core_minimize_hostIPC_containers: {str(e)}",
                resource_id="unknown",
                resource_name="unknown",
                resource_type="Pod",
                severity=CheckSeverity.HIGH
            ))

        return findings

"""
Minimize the admission of privileged containers

This check ensures that Kubernetes clusters are configured to minimize the admission of privileged containers, which have access to all Linux Kernel capabilities and devices. The use of privileged containers should be controlled and restricted to specific use-cases.
"""

from typing import List
from kubernetes import client
from kubernetes_checks.base import KubernetesCheckBase
from utility.base_reporting import CheckResult, CheckStatus, CheckSeverity

class core_minimize_privileged_containers(KubernetesCheckBase):
    """Minimize the admission of privileged containers"""

    def execute(self) -> List[CheckResult]:
        findings = []
        try:
            # Get all pods across namespaces
            v1_api = client.CoreV1Api(self.provider)
            all_pods = v1_api.list_pod_for_all_namespaces()
            
            for pod in all_pods.items:
                check_passed = True
                privileged_containers = []
                
                # Check all containers (including init containers)
                containers = pod.spec.containers or []
                init_containers = pod.spec.init_containers or []
                ephemeral_containers = pod.spec.ephemeral_containers or []
                
                for container in containers + init_containers + ephemeral_containers:
                    if (
                        container.security_context
                        and getattr(container.security_context, 'privileged', False)
                    ):
                        check_passed = False
                        privileged_containers.append(container.name)
                
                result = CheckResult(
                    check_id="core_minimize_privileged_containers",
                    check_name="Minimize the admission of privileged containers",
                    status=CheckStatus.PASS if check_passed else CheckStatus.FAIL,
                    status_extended=(
                        f"Pod {pod.metadata.name} does not contain privileged containers."
                        if check_passed else
                        f"Pod {pod.metadata.name} contains privileged containers: {', '.join(privileged_containers)}."
                    ),
                    resource_id=pod.metadata.name,
                    resource_name=pod.metadata.name,
                    resource_type="Pod",
                    namespace=pod.metadata.namespace,
                    severity=CheckSeverity.HIGH
                )
                
                if not check_passed:
                    result.recommendations = [
                        "Avoid running containers in privileged mode",
                        "Use security contexts with minimal required privileges",
                        "Consider using Pod Security Standards"
                    ]
                
                findings.append(result)

        except Exception as e:
            findings.append(CheckResult(
                check_id="core_minimize_privileged_containers",
                check_name="Minimize the admission of privileged containers",
                status=CheckStatus.ERROR,
                status_extended=f"Error checking core_minimize_privileged_containers: {str(e)}",
                resource_id="unknown",
                resource_name="unknown",
                resource_type="Pod",
                severity=CheckSeverity.HIGH
            ))

        return findings

"""
Minimize the admission of containers with assigned capabilities

This check ensures that Kubernetes clusters are configured to minimize the admission of containers with specific Linux capabilities assigned, reducing the attack surface.
"""

from typing import List
from kubernetes import client
from kubernetes_checks.base import KubernetesCheckBase
from utility.base_reporting import CheckResult, CheckStatus, CheckSeverity

class core_minimize_containers_capabilities_assigned(KubernetesCheckBase):
    """Minimize the admission of containers with assigned capabilities"""

    def execute(self) -> List[CheckResult]:
        findings = []
        try:
            # Get all pods across namespaces
            v1_api = client.CoreV1Api(self.provider)
            all_pods = v1_api.list_pod_for_all_namespaces()
            
            for pod in all_pods.items:
                check_passed = True
                assigned_capabilities_containers = []
                
                # Check all containers (including init containers)
                containers = pod.spec.containers or []
                init_containers = pod.spec.init_containers or []
                ephemeral_containers = pod.spec.ephemeral_containers or []
                
                for container in containers + init_containers + ephemeral_containers:
                    if (
                        container.security_context
                        and getattr(container.security_context, 'capabilities', None)
                        and (
                            (getattr(container.security_context.capabilities, 'add', None) and len(container.security_context.capabilities.add) > 0) or
                            (getattr(container.security_context.capabilities, 'drop', None) and len(container.security_context.capabilities.drop) > 0)
                        )
                    ):
                        check_passed = False
                        capabilities_info = []
                        if getattr(container.security_context.capabilities, 'add', None):
                            capabilities_info.append(f"add:{', '.join(container.security_context.capabilities.add)}")
                        if getattr(container.security_context.capabilities, 'drop', None):
                            capabilities_info.append(f"drop:{', '.join(container.security_context.capabilities.drop)}")
                        assigned_capabilities_containers.append(f"{container.name}({', '.join(capabilities_info)})")
                
                result = CheckResult(
                    check_id="core_minimize_containers_capabilities_assigned",
                    check_name="Minimize the admission of containers with assigned capabilities",
                    status=CheckStatus.PASS if check_passed else CheckStatus.FAIL,
                    status_extended=(
                        f"Pod {pod.metadata.name} does not have containers with assigned capabilities."
                        if check_passed else
                        f"Pod {pod.metadata.name} contains containers with assigned capabilities: {', '.join(assigned_capabilities_containers)}."
                    ),
                    resource_id=pod.metadata.name,
                    resource_name=pod.metadata.name,
                    resource_type="Pod",
                    namespace=pod.metadata.namespace,
                    severity=CheckSeverity.HIGH
                )
                
                if not check_passed:
                    result.recommendations = [
                        "Avoid assigning specific Linux capabilities unless necessary",
                        "Use the principle of least privilege",
                        "Consider using Pod Security Standards",
                        "Review and justify each capability assignment"
                    ]
                
                findings.append(result)

        except Exception as e:
            findings.append(CheckResult(
                check_id="core_minimize_containers_capabilities_assigned",
                check_name="Minimize the admission of containers with assigned capabilities",
                status=CheckStatus.ERROR,
                status_extended=f"Error checking core_minimize_containers_capabilities_assigned: {str(e)}",
                resource_id="unknown",
                resource_name="unknown",
                resource_type="Pod",
                severity=CheckSeverity.HIGH
            ))

        return findings

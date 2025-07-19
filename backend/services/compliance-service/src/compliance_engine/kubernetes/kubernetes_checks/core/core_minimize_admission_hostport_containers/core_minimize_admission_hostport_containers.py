"""
Minimize the admission of containers which use HostPorts

This check ensures that Kubernetes clusters are configured to minimize the admission of containers that require the use of HostPorts. This helps maintain network policy controls and reduce security risks.
"""

from typing import List
from kubernetes import client
from kubernetes_checks.base import KubernetesCheckBase
from utility.base_reporting import CheckResult, CheckStatus, CheckSeverity

class core_minimize_admission_hostport_containers(KubernetesCheckBase):
    """Minimize the admission of containers which use HostPorts"""

    def execute(self) -> List[CheckResult]:
        findings = []
        try:
            # Get all pods across namespaces
            v1_api = client.CoreV1Api(self.provider)
            all_pods = v1_api.list_pod_for_all_namespaces()
            
            for pod in all_pods.items:
                check_passed = True
                hostport_containers = []
                
                # Check all containers (including init containers)
                containers = pod.spec.containers or []
                init_containers = pod.spec.init_containers or []
                ephemeral_containers = pod.spec.ephemeral_containers or []
                
                for container in containers + init_containers + ephemeral_containers:
                    if container.ports:
                        for port in container.ports:
                            if port.host_port and port.host_port > 0:
                                check_passed = False
                                hostport_containers.append(f"{container.name}:{port.host_port}")
                
                result = CheckResult(
                    check_id="core_minimize_admission_hostport_containers",
                    check_name="Minimize the admission of containers which use HostPorts",
                    status=CheckStatus.PASS if check_passed else CheckStatus.FAIL,
                    status_extended=(
                        f"Pod {pod.metadata.name} does not use HostPorts."
                        if check_passed else
                        f"Pod {pod.metadata.name} uses HostPorts: {', '.join(hostport_containers)}."
                    ),
                    resource_id=pod.metadata.name,
                    resource_name=pod.metadata.name,
                    resource_type="Pod",
                    namespace=pod.metadata.namespace,
                    severity=CheckSeverity.HIGH
                )
                
                if not check_passed:
                    result.recommendations = [
                        "Avoid using hostPorts unless absolutely necessary",
                        "Use Kubernetes services for external access",
                        "Consider using NodePort or LoadBalancer services instead",
                        "Use network policies to control pod-to-pod communication"
                    ]
                
                findings.append(result)

        except Exception as e:
            findings.append(CheckResult(
                check_id="core_minimize_admission_hostport_containers",
                check_name="Minimize the admission of containers which use HostPorts",
                status=CheckStatus.ERROR,
                status_extended=f"Error checking core_minimize_admission_hostport_containers: {str(e)}",
                resource_id="unknown",
                resource_name="unknown",
                resource_type="Pod",
                severity=CheckSeverity.HIGH
            ))

        return findings

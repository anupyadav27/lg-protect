"""
Ensure containers use a non-default seccomp profile

This check ensures that Kubernetes clusters are configured to use custom seccomp profiles instead of the default Docker profile, which provides better security controls.
"""

from typing import List
from kubernetes import client
from kubernetes_checks.base import KubernetesCheckBase
from utility.base_reporting import CheckResult, CheckStatus, CheckSeverity

class core_seccomp_profile_docker_default(KubernetesCheckBase):
    """Ensure containers use a non-default seccomp profile"""

    def execute(self) -> List[CheckResult]:
        findings = []
        try:
            # Get all pods across namespaces
            v1_api = client.CoreV1Api(self.provider)
            all_pods = v1_api.list_pod_for_all_namespaces()
            
            for pod in all_pods.items:
                check_passed = True
                default_seccomp_containers = []
                
                # Check all containers (including init containers)
                containers = pod.spec.containers or []
                init_containers = pod.spec.init_containers or []
                ephemeral_containers = pod.spec.ephemeral_containers or []
                
                for container in containers + init_containers + ephemeral_containers:
                    if (
                        container.security_context
                        and getattr(container.security_context, 'seccomp_profile', None)
                        and getattr(container.security_context.seccomp_profile, 'type', None) == 'RuntimeDefault'
                    ):
                        check_passed = False
                        default_seccomp_containers.append(container.name)
                
                result = CheckResult(
                    check_id="core_seccomp_profile_docker_default",
                    check_name="Ensure containers use a non-default seccomp profile",
                    status=CheckStatus.PASS if check_passed else CheckStatus.FAIL,
                    status_extended=(
                        f"Pod {pod.metadata.name} does not use default seccomp profile."
                        if check_passed else
                        f"Pod {pod.metadata.name} contains containers using default seccomp profile: {', '.join(default_seccomp_containers)}."
                    ),
                    resource_id=pod.metadata.name,
                    resource_name=pod.metadata.name,
                    resource_type="Pod",
                    namespace=pod.metadata.namespace,
                    severity=CheckSeverity.MEDIUM
                )
                
                if not check_passed:
                    result.recommendations = [
                        "Use custom seccomp profiles instead of default",
                        "Configure seccomp profiles for better security",
                        "Consider using Pod Security Standards",
                        "Review and customize seccomp policies"
                    ]
                
                findings.append(result)

        except Exception as e:
            findings.append(CheckResult(
                check_id="core_seccomp_profile_docker_default",
                check_name="Ensure containers use a non-default seccomp profile",
                status=CheckStatus.ERROR,
                status_extended=f"Error checking core_seccomp_profile_docker_default: {str(e)}",
                resource_id="unknown",
                resource_name="unknown",
                resource_type="Pod",
                severity=CheckSeverity.MEDIUM
            ))

        return findings

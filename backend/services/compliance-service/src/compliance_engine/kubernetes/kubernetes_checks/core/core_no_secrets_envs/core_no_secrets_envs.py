"""
Prefer using secrets as files over secrets as environment variables

This check ensures that secrets in Kubernetes are used as files rather than environment variables. Using secrets as files is safer, as it reduces the risk of exposing sensitive data through application logs.
"""

from typing import List
from kubernetes import client
from kubernetes_checks.base import KubernetesCheckBase
from utility.base_reporting import CheckResult, CheckStatus, CheckSeverity

class core_no_secrets_envs(KubernetesCheckBase):
    """Prefer using secrets as files over secrets as environment variables"""

    def execute(self) -> List[CheckResult]:
        findings = []
        try:
            # Get all pods across namespaces
            v1_api = client.CoreV1Api(self.provider)
            all_pods = v1_api.list_pod_for_all_namespaces()
            
            for pod in all_pods.items:
                check_passed = True
                secret_envs = []
                
                # Check all containers (including init containers)
                containers = pod.spec.containers or []
                init_containers = pod.spec.init_containers or []
                ephemeral_containers = pod.spec.ephemeral_containers or []
                
                for container in containers + init_containers + ephemeral_containers:
                    if container.env:
                        for env_var in container.env:
                            if env_var.name and env_var.name.lower() in ["password", "secret", "key", "token", "credential", "api_key", "private_key"]:
                                check_passed = False
                                secret_envs.append(f"{container.name}:{env_var.name}")
                
                result = CheckResult(
                    check_id="core_no_secrets_envs",
                    check_name="Prefer using secrets as files over secrets as environment variables",
                    status=CheckStatus.PASS if check_passed else CheckStatus.FAIL,
                    status_extended=(
                        f"Pod {pod.metadata.name} does not contain secrets in environment variables."
                        if check_passed else
                        f"Pod {pod.metadata.name} contains potential secrets in environment variables: {', '.join(secret_envs)}."
                    ),
                    resource_id=pod.metadata.name,
                    resource_name=pod.metadata.name,
                    resource_type="Pod",
                    namespace=pod.metadata.namespace,
                    severity=CheckSeverity.MEDIUM
                )
                
                if not check_passed:
                    result.recommendations = [
                        "Use Kubernetes secrets instead of environment variables",
                        "Mount secrets as files rather than environment variables",
                        "Avoid storing sensitive data in environment variables",
                        "Use secret volumes for sensitive data"
                    ]
                
                findings.append(result)

        except Exception as e:
            findings.append(CheckResult(
                check_id="core_no_secrets_envs",
                check_name="Prefer using secrets as files over secrets as environment variables",
                status=CheckStatus.ERROR,
                status_extended=f"Error checking core_no_secrets_envs: {str(e)}",
                resource_id="unknown",
                resource_name="unknown",
                resource_type="Pod",
                severity=CheckSeverity.MEDIUM
            ))

        return findings

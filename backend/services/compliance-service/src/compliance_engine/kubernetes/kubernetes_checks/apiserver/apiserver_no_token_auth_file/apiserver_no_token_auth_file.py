"""
Ensure that the --token-auth-file parameter is not set

This check ensures that the Kubernetes API server is not using static token-based authentication, which is less secure. Static tokens are stored in clear-text and lack features like revocation or rotation without restarting the API server.
"""

from typing import List
from kubernetes import client
from kubernetes_checks.base import KubernetesCheckBase
from utility.base_reporting import CheckResult, CheckStatus, CheckSeverity

class apiserver_no_token_auth_file(KubernetesCheckBase):
    """Ensure that the --token-auth-file parameter is not set"""

    def execute(self) -> List[CheckResult]:
        findings = []
        try:
            v1_api = client.CoreV1Api(self.provider)
            api_server_pods = v1_api.list_namespaced_pod(
                namespace="kube-system",
                label_selector="component=kube-apiserver"
            )

            for pod in api_server_pods.items:
                check_passed = True
                for container in pod.spec.containers:
                    args = container.args or []
                    for i, arg in enumerate(args):
                        # Handle --token-auth-file=/path and --token-auth-file /path
                        if arg.startswith("--token-auth-file="):
                            check_passed = False
                            break
                        elif arg == "--token-auth-file" and i + 1 < len(args):
                            check_passed = False
                            break
                    if not check_passed:
                        break

                result = CheckResult(
                    check_id="apiserver_no_token_auth_file",
                    check_name="Ensure that the --token-auth-file parameter is not set",
                    status=CheckStatus.PASS if check_passed else CheckStatus.FAIL,
                    status_extended=(
                        f"API Server does not have token-auth-file enabled in pod {pod.metadata.name}."
                        if check_passed else
                        f"API Server has token-auth-file enabled in pod {pod.metadata.name}."
                    ),
                    resource_id=pod.metadata.name,
                    resource_name=pod.metadata.name,
                    resource_type="Pod",
                    namespace="kube-system",
                    severity=CheckSeverity.HIGH
                )
                if not check_passed:
                    result.recommendations = [
                        "Replace token-based authentication with more secure mechanisms like client certificate authentication. Ensure the --token-auth-file argument is not used in the API server configuration."
                    ]
                findings.append(result)

        except Exception as e:
            findings.append(CheckResult(
                check_id="apiserver_no_token_auth_file",
                check_name="Ensure that the --token-auth-file parameter is not set",
                status=CheckStatus.ERROR,
                status_extended=f"Error checking apiserver_no_token_auth_file: {str(e)}",
                resource_id="unknown",
                resource_name="unknown",
                resource_type="Pod",
                severity=CheckSeverity.HIGH
            ))

        return findings

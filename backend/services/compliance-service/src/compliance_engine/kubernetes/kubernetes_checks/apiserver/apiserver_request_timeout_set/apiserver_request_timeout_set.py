"""
Ensure that the --request-timeout argument is set as appropriate

This check verifies that the Kubernetes API server is configured with an appropriate global request timeout. Setting a suitable --request-timeout value ensures the API server can handle requests efficiently without exhausting resources, especially in cases of slower connections or high-volume data requests.
"""

from typing import List
from kubernetes import client
from kubernetes_checks.base import KubernetesCheckBase
from utility.base_reporting import CheckResult, CheckStatus, CheckSeverity

class apiserver_request_timeout_set(KubernetesCheckBase):
    """Ensure that the --request-timeout argument is set as appropriate"""

    def execute(self) -> List[CheckResult]:
        findings = []
        try:
            v1_api = client.CoreV1Api(self.provider)
            api_server_pods = v1_api.list_namespaced_pod(
                namespace="kube-system",
                label_selector="component=kube-apiserver"
            )

            for pod in api_server_pods.items:
                check_passed = False
                for container in pod.spec.containers:
                    args = container.args or []
                    for i, arg in enumerate(args):
                        # Handle --request-timeout=VALUE and --request-timeout VALUE
                        if arg.startswith("--request-timeout="):
                            timeout_value = arg.split("=", 1)[1]
                            if timeout_value:
                                check_passed = True
                                break
                        elif arg == "--request-timeout" and i + 1 < len(args):
                            timeout_value = args[i + 1]
                            if timeout_value:
                                check_passed = True
                                break
                    if check_passed:
                        break

                result = CheckResult(
                    check_id="apiserver_request_timeout_set",
                    check_name="Ensure that the --request-timeout argument is set as appropriate",
                    status=CheckStatus.PASS if check_passed else CheckStatus.FAIL,
                    status_extended=(
                        f"Request timeout is set appropriately in pod {pod.metadata.name}."
                        if check_passed else
                        f"Configuration is not properly set in pod {pod.metadata.name}."
                    ),
                    resource_id=pod.metadata.name,
                    resource_name=pod.metadata.name,
                    resource_type="Pod",
                    namespace="kube-system",
                    severity=CheckSeverity.MEDIUM
                )
                if not check_passed:
                    result.recommendations = [
                        "Set the API server request timeout to a value that balances resource usage efficiency and the needs of your environment, considering connection speeds and data volumes."
                    ]
                findings.append(result)

        except Exception as e:
            findings.append(CheckResult(
                check_id="apiserver_request_timeout_set",
                check_name="Ensure that the --request-timeout argument is set as appropriate",
                status=CheckStatus.ERROR,
                status_extended=f"Error checking apiserver_request_timeout_set: {str(e)}",
                resource_id="unknown",
                resource_name="unknown",
                resource_type="Pod",
                severity=CheckSeverity.MEDIUM
            ))

        return findings

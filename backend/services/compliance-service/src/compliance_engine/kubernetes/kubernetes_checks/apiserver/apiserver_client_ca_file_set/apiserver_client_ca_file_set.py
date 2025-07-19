"""
Ensure that the --client-ca-file argument is set as appropriate

This check ensures that the Kubernetes API server is configured with the --client-ca-file argument, specifying the CA file for client authentication. This setting enables the API server to authenticate clients using certificates signed by the CA and is crucial for secure communication.
"""

from typing import List
from kubernetes import client
from kubernetes_checks.base import KubernetesCheckBase
from utility.base_reporting import CheckResult, CheckStatus, CheckSeverity

class apiserver_client_ca_file_set(KubernetesCheckBase):
    """Ensure that the --client-ca-file argument is set as appropriate"""

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
                        # Handle --client-ca-file=/path/to/ca and --client-ca-file /path/to/ca
                        if arg.startswith("--client-ca-file="):
                            ca_path = arg.split("=", 1)[1]
                            if ca_path:
                                check_passed = True
                                break
                        elif arg == "--client-ca-file" and i + 1 < len(args):
                            ca_path = args[i + 1]
                            if ca_path:
                                check_passed = True
                                break
                    if check_passed:
                        break

                result = CheckResult(
                    check_id="apiserver_client_ca_file_set",
                    check_name="Ensure that the --client-ca-file argument is set as appropriate",
                    status=CheckStatus.PASS if check_passed else CheckStatus.FAIL,
                    status_extended=(
                        f"API server is configured with a client CA file in pod {pod.metadata.name}."
                        if check_passed else
                        f"Configuration is not properly set in pod {pod.metadata.name}."
                    ),
                    resource_id=pod.metadata.name,
                    resource_name=pod.metadata.name,
                    resource_type="Pod",
                    namespace="kube-system",
                    severity=CheckSeverity.HIGH
                )
                if not check_passed:
                    result.recommendations = [
                        "Ensure the API server is configured with a client CA file for secure client authentication."
                    ]
                findings.append(result)

        except Exception as e:
            findings.append(CheckResult(
                check_id="apiserver_client_ca_file_set",
                check_name="Ensure that the --client-ca-file argument is set as appropriate",
                status=CheckStatus.ERROR,
                status_extended=f"Error checking apiserver_client_ca_file_set: {str(e)}",
                resource_id="unknown",
                resource_name="unknown",
                resource_type="Pod",
                severity=CheckSeverity.HIGH
            ))

        return findings

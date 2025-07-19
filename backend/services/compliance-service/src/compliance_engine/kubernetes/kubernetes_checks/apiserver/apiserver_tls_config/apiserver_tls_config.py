"""
Ensure that the --tls-cert-file and --tls-private-key-file arguments are set as appropriate

This check ensures that the Kubernetes API server is configured with TLS for secure communication. The --tls-cert-file and --tls-private-key-file arguments should be set to enable TLS encryption, thereby securing sensitive data transmitted to and from the API server.
"""

from typing import List
from kubernetes import client
from kubernetes_checks.base import KubernetesCheckBase
from utility.base_reporting import CheckResult, CheckStatus, CheckSeverity

class apiserver_tls_config(KubernetesCheckBase):
    """Ensure that the --tls-cert-file and --tls-private-key-file arguments are set as appropriate"""

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
                cert_set = False
                key_set = False
                for container in pod.spec.containers:
                    args = container.args or []
                    for i, arg in enumerate(args):
                        # Handle --tls-cert-file and --tls-private-key-file (both = and space)
                        if arg.startswith("--tls-cert-file="):
                            cert_path = arg.split("=", 1)[1]
                            if cert_path:
                                cert_set = True
                        elif arg == "--tls-cert-file" and i + 1 < len(args):
                            cert_path = args[i + 1]
                            if cert_path:
                                cert_set = True
                        if arg.startswith("--tls-private-key-file="):
                            key_path = arg.split("=", 1)[1]
                            if key_path:
                                key_set = True
                        elif arg == "--tls-private-key-file" and i + 1 < len(args):
                            key_path = args[i + 1]
                            if key_path:
                                key_set = True
                    if cert_set and key_set:
                        check_passed = True
                        break

                result = CheckResult(
                    check_id="apiserver_tls_config",
                    check_name="Ensure that the --tls-cert-file and --tls-private-key-file arguments are set as appropriate",
                    status=CheckStatus.PASS if check_passed else CheckStatus.FAIL,
                    status_extended=(
                        f"TLS certificate and key are set appropriately in pod {pod.metadata.name}."
                        if check_passed else
                        f"TLS certificate and/or key are not set in pod {pod.metadata.name}."
                    ),
                    resource_id=pod.metadata.name,
                    resource_name=pod.metadata.name,
                    resource_type="Pod",
                    namespace="kube-system",
                    severity=CheckSeverity.HIGH
                )
                if not check_passed:
                    result.recommendations = [
                        "Ensure TLS is enabled and properly configured for the API server to secure communications."
                    ]
                findings.append(result)

        except Exception as e:
            findings.append(CheckResult(
                check_id="apiserver_tls_config",
                check_name="Ensure that the --tls-cert-file and --tls-private-key-file arguments are set as appropriate",
                status=CheckStatus.ERROR,
                status_extended=f"Error checking apiserver_tls_config: {str(e)}",
                resource_id="unknown",
                resource_name="unknown",
                resource_type="Pod",
                severity=CheckSeverity.HIGH
            ))

        return findings

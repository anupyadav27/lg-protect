"""
Ensure that the --kubelet-client-certificate and --kubelet-client-key arguments are set as appropriate

This check ensures that the Kubernetes API server is set up with certificate-based authentication to the kubelet. This setup requires the --kubelet-client-certificate and --kubelet-client-key arguments in the kube-apiserver configuration to be set, ensuring secure communication between the API server and kubelets.
"""

from typing import List
from kubernetes import client
from kubernetes_checks.base import KubernetesCheckBase
from utility.base_reporting import CheckResult, CheckStatus, CheckSeverity

class apiserver_kubelet_tls_auth(KubernetesCheckBase):
    """Ensure that the --kubelet-client-certificate and --kubelet-client-key arguments are set as appropriate"""

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
                    cert_set = False
                    key_set = False
                    for i, arg in enumerate(args):
                        # Handle --kubelet-client-certificate and --kubelet-client-key (both = and space)
                        if arg.startswith("--kubelet-client-certificate="):
                            cert_path = arg.split("=", 1)[1]
                            if cert_path:
                                cert_set = True
                        elif arg == "--kubelet-client-certificate" and i + 1 < len(args):
                            cert_path = args[i + 1]
                            if cert_path:
                                cert_set = True
                        if arg.startswith("--kubelet-client-key="):
                            key_path = arg.split("=", 1)[1]
                            if key_path:
                                key_set = True
                        elif arg == "--kubelet-client-key" and i + 1 < len(args):
                            key_path = args[i + 1]
                            if key_path:
                                key_set = True
                    if cert_set and key_set:
                        check_passed = True
                        break

                result = CheckResult(
                    check_id="apiserver_kubelet_tls_auth",
                    check_name="Ensure that the --kubelet-client-certificate and --kubelet-client-key arguments are set as appropriate",
                    status=CheckStatus.PASS if check_passed else CheckStatus.FAIL,
                    status_extended=(
                        f"API server is configured with kubelet client certificate and key in pod {pod.metadata.name}."
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
                        "Enable TLS authentication between the apiserver and kubelets by specifying the client certificate and key in the kube-apiserver configuration."
                    ]
                findings.append(result)

        except Exception as e:
            findings.append(CheckResult(
                check_id="apiserver_kubelet_tls_auth",
                check_name="Ensure that the --kubelet-client-certificate and --kubelet-client-key arguments are set as appropriate",
                status=CheckStatus.ERROR,
                status_extended=f"Error checking apiserver_kubelet_tls_auth: {str(e)}",
                resource_id="unknown",
                resource_name="unknown",
                resource_type="Pod",
                severity=CheckSeverity.HIGH
            ))

        return findings

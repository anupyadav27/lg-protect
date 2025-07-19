"""
Ensure that the --kubelet-certificate-authority argument is set as appropriate

This check ensures that the Kubernetes API server is set up with a specified certificate authority for kubelet connections, using the --kubelet-certificate-authority argument. This setup is crucial for verifying the kubelet's certificate to prevent man-in-the-middle attacks during connections from the apiserver to the kubelet.
"""

from typing import List
from kubernetes import client
from kubernetes_checks.base import KubernetesCheckBase
from utility.base_reporting import CheckResult, CheckStatus, CheckSeverity

class apiserver_kubelet_cert_auth(KubernetesCheckBase):
    """Ensure that the --kubelet-certificate-authority argument is set as appropriate"""

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
                        # Handle --kubelet-certificate-authority=/path and --kubelet-certificate-authority /path
                        if arg.startswith("--kubelet-certificate-authority="):
                            ca_path = arg.split("=", 1)[1]
                            if ca_path:
                                check_passed = True
                                break
                        elif arg == "--kubelet-certificate-authority" and i + 1 < len(args):
                            ca_path = args[i + 1]
                            if ca_path:
                                check_passed = True
                                break
                    if check_passed:
                        break

                result = CheckResult(
                    check_id="apiserver_kubelet_cert_auth",
                    check_name="Ensure that the --kubelet-certificate-authority argument is set as appropriate",
                    status=CheckStatus.PASS if check_passed else CheckStatus.FAIL,
                    status_extended=(
                        f"API server is configured with a kubelet certificate authority in pod {pod.metadata.name}."
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
                        "Enable TLS verification between the apiserver and kubelets by specifying the certificate authority in the kube-apiserver configuration."
                    ]
                findings.append(result)

        except Exception as e:
            findings.append(CheckResult(
                check_id="apiserver_kubelet_cert_auth",
                check_name="Ensure that the --kubelet-certificate-authority argument is set as appropriate",
                status=CheckStatus.ERROR,
                status_extended=f"Error checking apiserver_kubelet_cert_auth: {str(e)}",
                resource_id="unknown",
                resource_name="unknown",
                resource_type="Pod",
                severity=CheckSeverity.HIGH
            ))

        return findings

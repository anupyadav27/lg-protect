"""
Ensure that the Controller Manager has RotateKubeletServerCertificate set to true

This check ensures that the Kubernetes Controller Manager is configured with RotateKubeletServerCertificate=true in the feature gates. This enables automatic rotation of kubelet server certificates, which is important for security.
"""

from typing import List
from kubernetes_checks.base import KubernetesCheckBase
from utility.base_reporting import CheckResult, CheckStatus, CheckSeverity

class controllermanager_rotate_kubelet_server_cert(KubernetesCheckBase):
    """Ensure that the Controller Manager has RotateKubeletServerCertificate set to true"""

    def execute(self) -> List[CheckResult]:
        findings = []
        try:
            v1_api = self.get_core_v1_api()  # Replace with your actual method to get the API client
            controller_manager_pods = v1_api.list_namespaced_pod(
                namespace="kube-system",
                label_selector="component=kube-controller-manager"
            )

            for pod in controller_manager_pods.items:
                check_passed = False
                for container in pod.spec.containers:
                    args = container.args or []
                    for i, arg in enumerate(args):
                        # Handle --feature-gates=... and --feature-gates ...
                        if arg.startswith("--feature-gates="):
                            gates = arg.split("=", 1)[1].split(",")
                            if "RotateKubeletServerCertificate=true" in [g.strip() for g in gates]:
                                check_passed = True
                                break
                        elif arg == "--feature-gates" and i + 1 < len(args):
                            gates = args[i + 1].split(",")
                            if "RotateKubeletServerCertificate=true" in [g.strip() for g in gates]:
                                check_passed = True
                                break
                    if check_passed:
                        break

                result = CheckResult(
                    check_id="controllermanager_rotate_kubelet_server_cert",
                    check_name="Ensure that the Controller Manager has RotateKubeletServerCertificate set to true",
                    status=CheckStatus.PASS if check_passed else CheckStatus.FAIL,
                    status_extended=(
                        f"Controller Manager has RotateKubeletServerCertificate set to true in pod {pod.metadata.name}."
                        if check_passed else
                        f"Controller Manager does not have RotateKubeletServerCertificate set to true in pod {pod.metadata.name}."
                    ),
                    resource_id=pod.metadata.name,
                    resource_name=pod.metadata.name,
                    resource_type="Pod",
                    namespace="kube-system",
                    severity=CheckSeverity.HIGH
                )
                if not check_passed:
                    result.recommendations = [
                        "Enable RotateKubeletServerCertificate=true in the Controller Manager feature gates to enable automatic rotation of kubelet server certificates."
                    ]
                findings.append(result)

        except Exception as e:
            findings.append(CheckResult(
                check_id="controllermanager_rotate_kubelet_server_cert",
                check_name="Ensure that the Controller Manager has RotateKubeletServerCertificate set to true",
                status=CheckStatus.ERROR,
                status_extended=f"Error checking controllermanager_rotate_kubelet_server_cert: {str(e)}",
                resource_id="unknown",
                resource_name="unknown",
                resource_type="Pod",
                severity=CheckSeverity.HIGH
            ))

        return findings

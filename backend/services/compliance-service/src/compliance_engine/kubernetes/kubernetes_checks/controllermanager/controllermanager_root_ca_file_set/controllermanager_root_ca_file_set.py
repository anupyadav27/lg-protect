"""
Ensure that the Controller Manager has the root CA file set

This check ensures that the Kubernetes Controller Manager is configured with the --root-ca-file argument, which is important for signing service account tokens and other security features.
"""

from typing import List
from kubernetes_checks.base import KubernetesCheckBase
from utility.base_reporting import CheckResult, CheckStatus, CheckSeverity

class controllermanager_root_ca_file_set(KubernetesCheckBase):
    """Ensure that the Controller Manager has the root CA file set"""

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
                        # Handle --root-ca-file=/path and --root-ca-file /path
                        if arg.startswith("--root-ca-file="):
                            ca_path = arg.split("=", 1)[1]
                            if ca_path:
                                check_passed = True
                                break
                        elif arg == "--root-ca-file" and i + 1 < len(args):
                            ca_path = args[i + 1]
                            if ca_path:
                                check_passed = True
                                break
                    if check_passed:
                        break

                result = CheckResult(
                    check_id="controllermanager_root_ca_file_set",
                    check_name="Ensure that the Controller Manager has the root CA file set",
                    status=CheckStatus.PASS if check_passed else CheckStatus.FAIL,
                    status_extended=(
                        f"Controller Manager has the root CA file set in pod {pod.metadata.name}."
                        if check_passed else
                        f"Controller Manager does not have the root CA file set in pod {pod.metadata.name}."
                    ),
                    resource_id=pod.metadata.name,
                    resource_name=pod.metadata.name,
                    resource_type="Pod",
                    namespace="kube-system",
                    severity=CheckSeverity.HIGH
                )
                if not check_passed:
                    result.recommendations = [
                        "Set the --root-ca-file argument in the Controller Manager configuration to enable secure service account token signing and verification."
                    ]
                findings.append(result)

        except Exception as e:
            findings.append(CheckResult(
                check_id="controllermanager_root_ca_file_set",
                check_name="Ensure that the Controller Manager has the root CA file set",
                status=CheckStatus.ERROR,
                status_extended=f"Error checking controllermanager_root_ca_file_set: {str(e)}",
                resource_id="unknown",
                resource_name="unknown",
                resource_type="Pod",
                severity=CheckSeverity.HIGH
            ))

        return findings

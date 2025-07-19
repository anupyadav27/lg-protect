"""
Ensure that the Controller Manager has the service account private key file set

This check ensures that the Kubernetes Controller Manager is configured with the --service-account-private-key-file argument, which is important for signing service account tokens securely.
"""

from typing import List
from kubernetes_checks.base import KubernetesCheckBase
from utility.base_reporting import CheckResult, CheckStatus, CheckSeverity

class controllermanager_service_account_private_key_file(KubernetesCheckBase):
    """Ensure that the Controller Manager has the service account private key file set"""

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
                        # Handle --service-account-private-key-file=/path and --service-account-private-key-file /path
                        if arg.startswith("--service-account-private-key-file="):
                            key_path = arg.split("=", 1)[1]
                            if key_path:
                                check_passed = True
                                break
                        elif arg == "--service-account-private-key-file" and i + 1 < len(args):
                            key_path = args[i + 1]
                            if key_path:
                                check_passed = True
                                break
                    if check_passed:
                        break

                result = CheckResult(
                    check_id="controllermanager_service_account_private_key_file",
                    check_name="Ensure that the Controller Manager has the service account private key file set",
                    status=CheckStatus.PASS if check_passed else CheckStatus.FAIL,
                    status_extended=(
                        f"Controller Manager has the service account private key file set in pod {pod.metadata.name}."
                        if check_passed else
                        f"Controller Manager does not have the service account private key file set in pod {pod.metadata.name}."
                    ),
                    resource_id=pod.metadata.name,
                    resource_name=pod.metadata.name,
                    resource_type="Pod",
                    namespace="kube-system",
                    severity=CheckSeverity.HIGH
                )
                if not check_passed:
                    result.recommendations = [
                        "Set the --service-account-private-key-file argument in the Controller Manager configuration to enable secure service account token signing."
                    ]
                findings.append(result)

        except Exception as e:
            findings.append(CheckResult(
                check_id="controllermanager_service_account_private_key_file",
                check_name="Ensure that the Controller Manager has the service account private key file set",
                status=CheckStatus.ERROR,
                status_extended=f"Error checking controllermanager_service_account_private_key_file: {str(e)}",
                resource_id="unknown",
                resource_name="unknown",
                resource_type="Pod",
                severity=CheckSeverity.HIGH
            ))

        return findings

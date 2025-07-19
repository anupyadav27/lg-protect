"""
Ensure that the Controller Manager is not using service account credentials

This check ensures that the Kubernetes Controller Manager is not configured with --use-service-account-credentials=true. This setting can be a security risk as it allows the controller manager to use service account tokens for authentication.
"""

from typing import List
from kubernetes_checks.base import KubernetesCheckBase
from utility.base_reporting import CheckResult, CheckStatus, CheckSeverity

class controllermanager_service_account_credentials(KubernetesCheckBase):
    """Ensure that the Controller Manager is not using service account credentials"""

    def execute(self) -> List[CheckResult]:
        findings = []
        try:
            v1_api = self.get_core_v1_api()  # Replace with your actual method to get the API client
            controller_manager_pods = v1_api.list_namespaced_pod(
                namespace="kube-system",
                label_selector="component=kube-controller-manager"
            )

            for pod in controller_manager_pods.items:
                check_passed = True
                for container in pod.spec.containers:
                    args = container.args or []
                    for i, arg in enumerate(args):
                        # Handle --use-service-account-credentials=true and --use-service-account-credentials true
                        if arg == "--use-service-account-credentials=true":
                            check_passed = False
                            break
                        elif arg == "--use-service-account-credentials" and i + 1 < len(args):
                            if args[i + 1].lower() == "true":
                                check_passed = False
                                break
                    if not check_passed:
                        break

                result = CheckResult(
                    check_id="controllermanager_service_account_credentials",
                    check_name="Ensure that the Controller Manager is not using service account credentials",
                    status=CheckStatus.PASS if check_passed else CheckStatus.FAIL,
                    status_extended=(
                        f"Controller Manager is not using service account credentials in pod {pod.metadata.name}."
                        if check_passed else
                        f"Controller Manager is using service account credentials in pod {pod.metadata.name}."
                    ),
                    resource_id=pod.metadata.name,
                    resource_name=pod.metadata.name,
                    resource_type="Pod",
                    namespace="kube-system",
                    severity=CheckSeverity.HIGH
                )
                if not check_passed:
                    result.recommendations = [
                        "Disable --use-service-account-credentials in the Controller Manager configuration to avoid potential security risks associated with service account token usage."
                    ]
                findings.append(result)

        except Exception as e:
            findings.append(CheckResult(
                check_id="controllermanager_service_account_credentials",
                check_name="Ensure that the Controller Manager is not using service account credentials",
                status=CheckStatus.ERROR,
                status_extended=f"Error checking controllermanager_service_account_credentials: {str(e)}",
                resource_id="unknown",
                resource_name="unknown",
                resource_type="Pod",
                severity=CheckSeverity.HIGH
            ))

        return findings

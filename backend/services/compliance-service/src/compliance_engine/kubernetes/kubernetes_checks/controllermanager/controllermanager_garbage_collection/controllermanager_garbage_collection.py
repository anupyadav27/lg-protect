"""
Ensure that the Controller Manager has an appropriate garbage collection threshold

This check ensures that the Kubernetes Controller Manager is configured with a non-default --terminated-pod-gc-threshold value, which controls the number of terminated pods to retain. Using the default value (12500) may not be suitable for all environments.
"""

from typing import List
from kubernetes_checks.base import KubernetesCheckBase
from utility.base_reporting import CheckResult, CheckStatus, CheckSeverity

class controllermanager_garbage_collection(KubernetesCheckBase):
    """Ensure that the Controller Manager has an appropriate garbage collection threshold"""

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
                    for arg in args:
                        if arg == "--terminated-pod-gc-threshold=12500":
                            check_passed = False
                            break
                    if not check_passed:
                        break

                result = CheckResult(
                    check_id="controllermanager_garbage_collection",
                    check_name="Ensure that the Controller Manager has an appropriate garbage collection threshold",
                    status=CheckStatus.PASS if check_passed else CheckStatus.FAIL,
                    status_extended=(
                        f"Controller Manager has an appropriate garbage collection threshold in pod {pod.metadata.name}."
                        if check_passed else
                        f"Controller Manager has the default garbage collection threshold in pod {pod.metadata.name}."
                    ),
                    resource_id=pod.metadata.name,
                    resource_name=pod.metadata.name,
                    resource_type="Pod",
                    namespace="kube-system",
                    severity=CheckSeverity.HIGH
                )
                if not check_passed:
                    result.recommendations = [
                        "Set a custom --terminated-pod-gc-threshold value in the Controller Manager configuration to suit your environment and avoid using the default (12500)."
                    ]
                findings.append(result)

        except Exception as e:
            findings.append(CheckResult(
                check_id="controllermanager_garbage_collection",
                check_name="Ensure that the Controller Manager has an appropriate garbage collection threshold",
                status=CheckStatus.ERROR,
                status_extended=f"Error checking controllermanager_garbage_collection: {str(e)}",
                resource_id="unknown",
                resource_name="unknown",
                resource_type="Pod",
                severity=CheckSeverity.HIGH
            ))

        return findings

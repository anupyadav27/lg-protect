"""
Ensure that the Controller Manager is bound to the loopback address

This check ensures that the Kubernetes Controller Manager is configured to bind only to the loopback address (127.0.0.1), which restricts access and enhances security.
"""

from typing import List
from kubernetes_checks.base import KubernetesCheckBase
from utility.base_reporting import CheckResult, CheckStatus, CheckSeverity

class controllermanager_bind_address(KubernetesCheckBase):
    """Ensure that the Controller Manager is bound to the loopback address"""

    def execute(self) -> List[CheckResult]:
        findings = []
        try:
            # You may need to implement or import a client to get controller manager pods, similar to apiserver checks
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
                        if arg.startswith("--bind-address=") and arg.split("=", 1)[1] == "127.0.0.1":
                            check_passed = True
                            break
                        elif arg == "--bind-address" and i + 1 < len(args) and args[i + 1] == "127.0.0.1":
                            check_passed = True
                            break
                        if arg.startswith("--address=") and arg.split("=", 1)[1] == "127.0.0.1":
                            check_passed = True
                            break
                        elif arg == "--address" and i + 1 < len(args) and args[i + 1] == "127.0.0.1":
                            check_passed = True
                            break
                    if check_passed:
                        break

                result = CheckResult(
                    check_id="controllermanager_bind_address",
                    check_name="Ensure that the Controller Manager is bound to the loopback address",
                    status=CheckStatus.PASS if check_passed else CheckStatus.FAIL,
                    status_extended=(
                        f"Controller Manager is bound to the loopback address in pod {pod.metadata.name}."
                        if check_passed else
                        f"Controller Manager is not bound to the loopback address in pod {pod.metadata.name}."
                    ),
                    resource_id=pod.metadata.name,
                    resource_name=pod.metadata.name,
                    resource_type="Pod",
                    namespace="kube-system",
                    severity=CheckSeverity.HIGH
                )
                if not check_passed:
                    result.recommendations = [
                        "Configure the Controller Manager to bind only to the loopback address (127.0.0.1) for enhanced security."
                    ]
                findings.append(result)

        except Exception as e:
            findings.append(CheckResult(
                check_id="controllermanager_bind_address",
                check_name="Ensure that the Controller Manager is bound to the loopback address",
                status=CheckStatus.ERROR,
                status_extended=f"Error checking controllermanager_bind_address: {str(e)}",
                resource_id="unknown",
                resource_name="unknown",
                resource_type="Pod",
                severity=CheckSeverity.HIGH
            ))

        return findings

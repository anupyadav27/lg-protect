"""
Ensure that profiling is disabled in the Controller Manager

This check ensures that profiling is disabled in the Kubernetes Controller Manager. Profiling should be disabled unless needed for troubleshooting, as it can expose sensitive performance data.
"""

from typing import List
from kubernetes_checks.base import KubernetesCheckBase
from utility.base_reporting import CheckResult, CheckStatus, CheckSeverity

class controllermanager_disable_profiling(KubernetesCheckBase):
    """Ensure that profiling is disabled in the Controller Manager"""

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
                        # Handle --profiling=false and --profiling false
                        if arg == "--profiling=false":
                            check_passed = True
                            break
                        elif arg == "--profiling" and i + 1 < len(args):
                            if args[i + 1].lower() == "false":
                                check_passed = True
                                break
                    if check_passed:
                        break

                result = CheckResult(
                    check_id="controllermanager_disable_profiling",
                    check_name="Ensure that profiling is disabled in the Controller Manager",
                    status=CheckStatus.PASS if check_passed else CheckStatus.FAIL,
                    status_extended=(
                        f"Controller Manager does not have profiling enabled in pod {pod.metadata.name}."
                        if check_passed else
                        f"Controller Manager has profiling enabled in pod {pod.metadata.name}."
                    ),
                    resource_id=pod.metadata.name,
                    resource_name=pod.metadata.name,
                    resource_type="Pod",
                    namespace="kube-system",
                    severity=CheckSeverity.HIGH
                )
                if not check_passed:
                    result.recommendations = [
                        "Disable profiling in the Controller Manager unless it is necessary for troubleshooting performance bottlenecks."
                    ]
                findings.append(result)

        except Exception as e:
            findings.append(CheckResult(
                check_id="controllermanager_disable_profiling",
                check_name="Ensure that profiling is disabled in the Controller Manager",
                status=CheckStatus.ERROR,
                status_extended=f"Error checking controllermanager_disable_profiling: {str(e)}",
                resource_id="unknown",
                resource_name="unknown",
                resource_type="Pod",
                severity=CheckSeverity.HIGH
            ))

        return findings

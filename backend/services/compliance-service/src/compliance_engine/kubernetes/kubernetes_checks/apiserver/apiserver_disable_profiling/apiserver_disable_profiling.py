"""
Ensure that the --profiling argument is set to false

This check ensures that profiling is disabled in the Kubernetes API server. Profiling generates extensive data about the system's performance and operations, which, if not needed, should be disabled to reduce the attack surface.
"""

from typing import List
from kubernetes import client
from kubernetes_checks.base import KubernetesCheckBase
from utility.base_reporting import CheckResult, CheckStatus, CheckSeverity

class apiserver_disable_profiling(KubernetesCheckBase):
    """Ensure that the --profiling argument is set to false"""

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
                    check_id="apiserver_disable_profiling",
                    check_name="Ensure that the --profiling argument is set to false",
                    status=CheckStatus.PASS if check_passed else CheckStatus.FAIL,
                    status_extended=(
                        f"Profiling is disabled in pod {pod.metadata.name}."
                        if check_passed else
                        f"Configuration is not properly set in pod {pod.metadata.name}."
                    ),
                    resource_id=pod.metadata.name,
                    resource_name=pod.metadata.name,
                    resource_type="Pod",
                    namespace="kube-system",
                    severity=CheckSeverity.MEDIUM
                )
                if not check_passed:
                    result.recommendations = [
                        "Disable profiling in the API server unless it is necessary for troubleshooting performance bottlenecks."
                    ]
                findings.append(result)

        except Exception as e:
            findings.append(CheckResult(
                check_id="apiserver_disable_profiling",
                check_name="Ensure that the --profiling argument is set to false",
                status=CheckStatus.ERROR,
                status_extended=f"Error checking apiserver_disable_profiling: {str(e)}",
                resource_id="unknown",
                resource_name="unknown",
                resource_type="Pod",
                severity=CheckSeverity.MEDIUM
            ))

        return findings

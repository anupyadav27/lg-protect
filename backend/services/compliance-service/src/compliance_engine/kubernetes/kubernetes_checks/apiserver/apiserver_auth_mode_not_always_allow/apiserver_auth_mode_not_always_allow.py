"""
Ensure that the --authorization-mode argument is not set to AlwaysAllow

This check ensures that the Kubernetes API server is not configured to always authorize all requests. The 'AlwaysAllow' mode bypasses all authorization checks, which should not be used on production clusters.
"""

from typing import List
from kubernetes import client
from kubernetes_checks.base import KubernetesCheckBase
from utility.base_reporting import CheckResult, CheckStatus, CheckSeverity

class apiserver_auth_mode_not_always_allow(KubernetesCheckBase):
    """Ensure that the --authorization-mode argument is not set to AlwaysAllow"""

    def execute(self) -> List[CheckResult]:
        findings = []
        try:
            v1_api = client.CoreV1Api(self.provider)
            api_server_pods = v1_api.list_namespaced_pod(
                namespace="kube-system",
                label_selector="component=kube-apiserver"
            )

            for pod in api_server_pods.items:
                check_passed = True
                for container in pod.spec.containers:
                    args = container.args or []
                    for i, arg in enumerate(args):
                        # Handle --authorization-mode=RBAC,Node,Webhook and --authorization-mode RBAC,Node,Webhook
                        if arg.startswith("--authorization-mode="):
                            modes = arg.split("=", 1)[1].split(",")
                            if "AlwaysAllow" in [m.strip() for m in modes]:
                                check_passed = False
                                break
                        elif arg == "--authorization-mode" and i + 1 < len(args):
                            modes = args[i + 1].split(",")
                            if "AlwaysAllow" in [m.strip() for m in modes]:
                                check_passed = False
                                break
                    if not check_passed:
                        break

                result = CheckResult(
                    check_id="apiserver_auth_mode_not_always_allow",
                    check_name="Ensure that the --authorization-mode argument is not set to AlwaysAllow",
                    status=CheckStatus.PASS if check_passed else CheckStatus.FAIL,
                    status_extended=(
                        f"API Server authorization mode does not include AlwaysAllow in pod {pod.metadata.name}."
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
                        "Ensure the API server is using a secure authorization mode, such as RBAC, and not set to AlwaysAllow."
                    ]
                findings.append(result)

        except Exception as e:
            findings.append(CheckResult(
                check_id="apiserver_auth_mode_not_always_allow",
                check_name="Ensure that the --authorization-mode argument is not set to AlwaysAllow",
                status=CheckStatus.ERROR,
                status_extended=f"Error checking apiserver_auth_mode_not_always_allow: {str(e)}",
                resource_id="unknown",
                resource_name="unknown",
                resource_type="Pod",
                severity=CheckSeverity.HIGH
            ))

        return findings

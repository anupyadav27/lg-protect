"""
Ensure that the --authorization-mode argument includes RBAC

This check verifies that Role Based Access Control (RBAC) is enabled in the Kubernetes API server's authorization mode. RBAC allows for fine-grained control over cluster operations and is recommended for secure and manageable access control.
"""

from typing import List
from kubernetes import client
from kubernetes_checks.base import KubernetesCheckBase
from utility.base_reporting import CheckResult, CheckStatus, CheckSeverity

class apiserver_auth_mode_include_rbac(KubernetesCheckBase):
    """Ensure that the --authorization-mode argument includes RBAC"""

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
                        # Handle --authorization-mode=RBAC,Node,Webhook and --authorization-mode RBAC,Node,Webhook
                        if arg.startswith("--authorization-mode="):
                            modes = arg.split("=", 1)[1].split(",")
                            if "RBAC" in [m.strip() for m in modes]:
                                check_passed = True
                                break
                        elif arg == "--authorization-mode" and i + 1 < len(args):
                            modes = args[i + 1].split(",")
                            if "RBAC" in [m.strip() for m in modes]:
                                check_passed = True
                                break
                    if check_passed:
                        break

                result = CheckResult(
                    check_id="apiserver_auth_mode_include_rbac",
                    check_name="Ensure that the --authorization-mode argument includes RBAC",
                    status=CheckStatus.PASS if check_passed else CheckStatus.FAIL,
                    status_extended=(
                        f"API Server authorization mode includes RBAC in pod {pod.metadata.name}."
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
                        "Ensure that the API server is configured with RBAC authorization mode for enhanced security and access control."
                    ]
                findings.append(result)

        except Exception as e:
            findings.append(CheckResult(
                check_id="apiserver_auth_mode_include_rbac",
                check_name="Ensure that the --authorization-mode argument includes RBAC",
                status=CheckStatus.ERROR,
                status_extended=f"Error checking apiserver_auth_mode_include_rbac: {str(e)}",
                resource_id="unknown",
                resource_name="unknown",
                resource_type="Pod",
                severity=CheckSeverity.HIGH
            ))

        return findings

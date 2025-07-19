"""
Ensure that the --audit-log-path argument is set

This check verifies that the Kubernetes API server is configured with an audit log path. Enabling audit logs helps in maintaining a chronological record of all activities and operations which can be critical for security analysis and troubleshooting.
"""

from typing import List
from kubernetes import client
from kubernetes_checks.base import KubernetesCheckBase
from utility.base_reporting import CheckResult, CheckStatus, CheckSeverity

class apiserver_audit_log_path_set(KubernetesCheckBase):
    """Ensure that the --audit-log-path argument is set"""

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
                        # Handle --audit-log-path=/some/path and --audit-log-path /some/path
                        if arg.startswith("--audit-log-path="):
                            path_value = arg.split("=", 1)[1]
                            if path_value:
                                check_passed = True
                                break
                        elif arg == "--audit-log-path" and i + 1 < len(args):
                            path_value = args[i + 1]
                            if path_value:
                                check_passed = True
                                break
                    if check_passed:
                        break

                result = CheckResult(
                    check_id="apiserver_audit_log_path_set",
                    check_name="Ensure that the --audit-log-path argument is set",
                    status=CheckStatus.PASS if check_passed else CheckStatus.FAIL,
                    status_extended=(
                        f"Audit log path is set in the API server in pod {pod.metadata.name}."
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
                        "Enable audit logging in the API server by specifying a valid path for --audit-log-path to ensure comprehensive activity logging within the cluster."
                    ]
                findings.append(result)

        except Exception as e:
            findings.append(CheckResult(
                check_id="apiserver_audit_log_path_set",
                check_name="Ensure that the --audit-log-path argument is set",
                status=CheckStatus.ERROR,
                status_extended=f"Error checking apiserver_audit_log_path_set: {str(e)}",
                resource_id="unknown",
                resource_name="unknown",
                resource_type="Pod",
                severity=CheckSeverity.HIGH
            ))

        return findings

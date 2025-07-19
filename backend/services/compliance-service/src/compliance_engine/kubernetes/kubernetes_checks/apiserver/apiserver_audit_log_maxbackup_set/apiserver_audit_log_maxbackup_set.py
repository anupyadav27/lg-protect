"""
Ensure that the --audit-log-maxbackup argument is set to 10 or as appropriate

This check ensures that the Kubernetes API server is configured with an appropriate number of audit log backups. Setting --audit-log-maxbackup to 10 or as per business requirements helps maintain a sufficient log backup for investigations or analysis.
"""

from typing import List
from kubernetes import client
from kubernetes_checks.base import KubernetesCheckBase
from utility.base_reporting import CheckResult, CheckStatus, CheckSeverity

class apiserver_audit_log_maxbackup_set(KubernetesCheckBase):
    """Ensure that the --audit-log-maxbackup argument is set to 10 or as appropriate"""

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
                        # Handle --audit-log-maxbackup=10
                        if arg.startswith("--audit-log-maxbackup="):
                            try:
                                value = int(arg.split("=", 1)[1])
                                if value >= 10:
                                    check_passed = True
                                    break
                            except Exception:
                                continue
                        # Handle --audit-log-maxbackup 10
                        elif arg == "--audit-log-maxbackup" and i + 1 < len(args):
                            try:
                                value = int(args[i + 1])
                                if value >= 10:
                                    check_passed = True
                                    break
                            except Exception:
                                continue
                    if check_passed:
                        break

                result = CheckResult(
                    check_id="apiserver_audit_log_maxbackup_set",
                    check_name="Ensure that the --audit-log-maxbackup argument is set to 10 or as appropriate",
                    status=CheckStatus.PASS if check_passed else CheckStatus.FAIL,
                    status_extended=(
                        f"Configuration is properly set in pod {pod.metadata.name}."
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
                        "Configure the API server audit log backup retention to 10 or as per your organization's requirements."
                    ]
                findings.append(result)

        except Exception as e:
            findings.append(CheckResult(
                check_id="apiserver_audit_log_maxbackup_set",
                check_name="Ensure that the --audit-log-maxbackup argument is set to 10 or as appropriate",
                status=CheckStatus.ERROR,
                status_extended=f"Error checking apiserver_audit_log_maxbackup_set: {str(e)}",
                resource_id="unknown",
                resource_name="unknown",
                resource_type="Pod",
                severity=CheckSeverity.MEDIUM
            ))

        return findings

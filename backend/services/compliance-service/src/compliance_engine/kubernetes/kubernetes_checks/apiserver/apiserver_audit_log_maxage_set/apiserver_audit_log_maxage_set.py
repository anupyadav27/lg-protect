"""
Ensure that the --audit-log-maxage argument is set to 30 or as appropriate

This check ensures that the Kubernetes API server is configured with an appropriate audit log retention period. Setting --audit-log-maxage to 30 or as per business requirements helps in maintaining logs for sufficient time to investigate past events.
"""

from typing import List
from kubernetes import client
from kubernetes_checks.base import KubernetesCheckBase
from utility.base_reporting import CheckResult, CheckStatus, CheckSeverity

class apiserver_audit_log_maxage_set(KubernetesCheckBase):
    """Ensure that the --audit-log-maxage argument is set to 30 or as appropriate"""

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
                    for arg in container.args or []:
                        # Support both --audit-log-maxage=30 and --audit-log-maxage 30
                        if arg.startswith("--audit-log-maxage"):
                            if "=" in arg:
                                try:
                                    value = int(arg.split("=")[1])
                                    if value >= 30:
                                        check_passed = True
                                except Exception:
                                    pass
                            else:
                                # Handle the case: --audit-log-maxage 30
                                idx = container.args.index(arg)
                                if idx + 1 < len(container.args):
                                    try:
                                        value = int(container.args[idx + 1])
                                        if value >= 30:
                                            check_passed = True
                                    except Exception:
                                        pass
                    if check_passed:
                        break

                result = CheckResult(
                    check_id="apiserver_audit_log_maxage_set",
                    check_name="Ensure that the --audit-log-maxage argument is set to 30 or as appropriate",
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
                        "Configure the API server audit log retention period to retain logs for at least 30 days or as per your organization's requirements."
                    ]
                findings.append(result)

        except Exception as e:
            findings.append(CheckResult(
                check_id="apiserver_audit_log_maxage_set",
                check_name="Ensure that the --audit-log-maxage argument is set to 30 or as appropriate",
                status=CheckStatus.ERROR,
                status_extended=f"Error checking apiserver_audit_log_maxage_set: {str(e)}",
                resource_id="unknown",
                resource_name="unknown",
                resource_type="Pod",
                severity=CheckSeverity.MEDIUM
            ))

        return findings

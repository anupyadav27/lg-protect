"""
Ensure that the admission control plugin AlwaysAdmit is not set

This check verifies that the Kubernetes API server is not configured with the AlwaysAdmit admission control plugin. The AlwaysAdmit plugin allows all requests without any filtering, which is a security risk and is deprecated.
"""

from typing import List
from kubernetes import client
from kubernetes_checks.base import KubernetesCheckBase
from utility.base_reporting import CheckResult, CheckStatus, CheckSeverity

class apiserver_no_always_admit_plugin(KubernetesCheckBase):
    """Ensure that the admission control plugin AlwaysAdmit is not set"""

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
                        # Check for AlwaysAdmit in --enable-admission-plugins
                        if arg.startswith("--enable-admission-plugins="):
                            plugins = arg.split("=", 1)[1].split(",")
                            if "AlwaysAdmit" in [p.strip() for p in plugins]:
                                check_passed = False
                                break
                        elif arg == "--enable-admission-plugins" and i + 1 < len(args):
                            plugins = args[i + 1].split(",")
                            if "AlwaysAdmit" in [p.strip() for p in plugins]:
                                check_passed = False
                                break
                    if not check_passed:
                        break

                result = CheckResult(
                    check_id="apiserver_no_always_admit_plugin",
                    check_name="Ensure that the admission control plugin AlwaysAdmit is not set",
                    status=CheckStatus.PASS if check_passed else CheckStatus.FAIL,
                    status_extended=(
                        f"AlwaysAdmit admission control plugin is not set in pod {pod.metadata.name}."
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
                        "Ensure the API server does not use the AlwaysAdmit admission control plugin to maintain proper security checks for all requests."
                    ]
                findings.append(result)

        except Exception as e:
            findings.append(CheckResult(
                check_id="apiserver_no_always_admit_plugin",
                check_name="Ensure that the admission control plugin AlwaysAdmit is not set",
                status=CheckStatus.ERROR,
                status_extended=f"Error checking apiserver_no_always_admit_plugin: {str(e)}",
                resource_id="unknown",
                resource_name="unknown",
                resource_type="Pod",
                severity=CheckSeverity.HIGH
            ))

        return findings

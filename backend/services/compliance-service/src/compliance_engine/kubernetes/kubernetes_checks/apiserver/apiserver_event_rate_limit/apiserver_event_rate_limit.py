"""
Ensure that the admission control plugin EventRateLimit is set

This check verifies if the Kubernetes API server is configured with the EventRateLimit admission control plugin. This plugin limits the rate of events accepted by the API Server, preventing potential DoS attacks by misbehaving workloads.
"""

from typing import List
from kubernetes import client
from kubernetes_checks.base import KubernetesCheckBase
from utility.base_reporting import CheckResult, CheckStatus, CheckSeverity

class apiserver_event_rate_limit(KubernetesCheckBase):
    """Ensure that the admission control plugin EventRateLimit is set"""

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
                        # Handle --enable-admission-plugins=... and --enable-admission-plugins ...
                        if arg.startswith("--enable-admission-plugins="):
                            plugins = arg.split("=", 1)[1].split(",")
                            if "EventRateLimit" in [p.strip() for p in plugins]:
                                check_passed = True
                                break
                        elif arg == "--enable-admission-plugins" and i + 1 < len(args):
                            plugins = args[i + 1].split(",")
                            if "EventRateLimit" in [p.strip() for p in plugins]:
                                check_passed = True
                                break
                    if check_passed:
                        break

                result = CheckResult(
                    check_id="apiserver_event_rate_limit",
                    check_name="Ensure that the admission control plugin EventRateLimit is set",
                    status=CheckStatus.PASS if check_passed else CheckStatus.FAIL,
                    status_extended=(
                        f"EventRateLimit admission control plugin is set in pod {pod.metadata.name}."
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
                        "Configure EventRateLimit as an admission control plugin for the API server to manage the rate of incoming events effectively."
                    ]
                findings.append(result)

        except Exception as e:
            findings.append(CheckResult(
                check_id="apiserver_event_rate_limit",
                check_name="Ensure that the admission control plugin EventRateLimit is set",
                status=CheckStatus.ERROR,
                status_extended=f"Error checking apiserver_event_rate_limit: {str(e)}",
                resource_id="unknown",
                resource_name="unknown",
                resource_type="Pod",
                severity=CheckSeverity.MEDIUM
            ))

        return findings

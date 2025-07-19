"""
Ensure that the admission control plugin SecurityContextDeny is set if PodSecurityPolicy is not used

This check verifies that the SecurityContextDeny admission control plugin is enabled in the Kubernetes API server if PodSecurityPolicy is not used. The SecurityContextDeny plugin denies pods that make use of certain SecurityContext fields which could allow privilege escalation.
"""

from typing import List
from kubernetes import client
from kubernetes_checks.base import KubernetesCheckBase
from utility.base_reporting import CheckResult, CheckStatus, CheckSeverity

class apiserver_security_context_deny_plugin(KubernetesCheckBase):
    """Ensure that the admission control plugin SecurityContextDeny is set if PodSecurityPolicy is not used"""

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
                pod_security_policy_set = False
                security_context_deny_set = False
                for container in pod.spec.containers:
                    args = container.args or []
                    for i, arg in enumerate(args):
                        # Check for SecurityContextDeny and PodSecurityPolicy in --enable-admission-plugins
                        if arg.startswith("--enable-admission-plugins="):
                            plugins = arg.split("=", 1)[1].split(",")
                            plugins = [p.strip() for p in plugins]
                            if "SecurityContextDeny" in plugins:
                                security_context_deny_set = True
                            if "PodSecurityPolicy" in plugins:
                                pod_security_policy_set = True
                        elif arg == "--enable-admission-plugins" and i + 1 < len(args):
                            plugins = args[i + 1].split(",")
                            plugins = [p.strip() for p in plugins]
                            if "SecurityContextDeny" in plugins:
                                security_context_deny_set = True
                            if "PodSecurityPolicy" in plugins:
                                pod_security_policy_set = True
                    # PASS if PodSecurityPolicy is set, or if SecurityContextDeny is set and PodSecurityPolicy is not set
                    if pod_security_policy_set or (security_context_deny_set and not pod_security_policy_set):
                        check_passed = True
                        break

                result = CheckResult(
                    check_id="apiserver_security_context_deny_plugin",
                    check_name="Ensure that the admission control plugin SecurityContextDeny is set if PodSecurityPolicy is not used",
                    status=CheckStatus.PASS if check_passed else CheckStatus.FAIL,
                    status_extended=(
                        f"PodSecurityPolicy is in use in pod {pod.metadata.name}."
                        if pod_security_policy_set else
                        f"SecurityContextDeny admission control plugin is set in pod {pod.metadata.name}."
                        if security_context_deny_set else
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
                        "Use SecurityContextDeny as an admission control plugin in the API server to enhance security, especially in the absence of PodSecurityPolicy."
                    ]
                findings.append(result)

        except Exception as e:
            findings.append(CheckResult(
                check_id="apiserver_security_context_deny_plugin",
                check_name="Ensure that the admission control plugin SecurityContextDeny is set if PodSecurityPolicy is not used",
                status=CheckStatus.ERROR,
                status_extended=f"Error checking apiserver_security_context_deny_plugin: {str(e)}",
                resource_id="unknown",
                resource_name="unknown",
                resource_type="Pod",
                severity=CheckSeverity.MEDIUM
            ))

        return findings

"""
Ensure that the admission control plugin NamespaceLifecycle is set

This check verifies that the NamespaceLifecycle admission control plugin is enabled in the Kubernetes API server. This plugin prevents the creation of objects in non-existent or terminating namespaces, enforcing the integrity of the namespace lifecycle and availability of new objects.
"""

from typing import List
from kubernetes import client
from kubernetes_checks.base import KubernetesCheckBase
from utility.base_reporting import CheckResult, CheckStatus, CheckSeverity

class apiserver_namespace_lifecycle_plugin(KubernetesCheckBase):
    """Ensure that the admission control plugin NamespaceLifecycle is set"""

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
                    enabled = False
                    disabled = False
                    for i, arg in enumerate(args):
                        # Check if NamespaceLifecycle is enabled
                        if arg.startswith("--enable-admission-plugins="):
                            plugins = arg.split("=", 1)[1].split(",")
                            if "NamespaceLifecycle" in [p.strip() for p in plugins]:
                                enabled = True
                        elif arg == "--enable-admission-plugins" and i + 1 < len(args):
                            plugins = args[i + 1].split(",")
                            if "NamespaceLifecycle" in [p.strip() for p in plugins]:
                                enabled = True
                        # Check if NamespaceLifecycle is disabled
                        if arg.startswith("--disable-admission-plugins="):
                            plugins = arg.split("=", 1)[1].split(",")
                            if "NamespaceLifecycle" in [p.strip() for p in plugins]:
                                disabled = True
                        elif arg == "--disable-admission-plugins" and i + 1 < len(args):
                            plugins = args[i + 1].split(",")
                            if "NamespaceLifecycle" in [p.strip() for p in plugins]:
                                disabled = True
                    if enabled and not disabled:
                        check_passed = True
                        break

                result = CheckResult(
                    check_id="apiserver_namespace_lifecycle_plugin",
                    check_name="Ensure that the admission control plugin NamespaceLifecycle is set",
                    status=CheckStatus.PASS if check_passed else CheckStatus.FAIL,
                    status_extended=(
                        f"NamespaceLifecycle admission control plugin is set in pod {pod.metadata.name}."
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
                        "Enable the NamespaceLifecycle admission control plugin in the API server to enforce proper namespace management."
                    ]
                findings.append(result)

        except Exception as e:
            findings.append(CheckResult(
                check_id="apiserver_namespace_lifecycle_plugin",
                check_name="Ensure that the admission control plugin NamespaceLifecycle is set",
                status=CheckStatus.ERROR,
                status_extended=f"Error checking apiserver_namespace_lifecycle_plugin: {str(e)}",
                resource_id="unknown",
                resource_name="unknown",
                resource_type="Pod",
                severity=CheckSeverity.MEDIUM
            ))

        return findings

"""
Ensure that the DenyServiceExternalIPs is set

This check ensures the DenyServiceExternalIPs admission controller is enabled, which rejects all new usage of the Service field externalIPs. Enabling this controller enhances security by preventing the misuse of the externalIPs field.
"""

from typing import List
from kubernetes import client
from kubernetes_checks.base import KubernetesCheckBase
from utility.base_reporting import CheckResult, CheckStatus, CheckSeverity

class apiserver_deny_service_external_ips(KubernetesCheckBase):
    """Ensure that the DenyServiceExternalIPs is set"""

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
                            if "DenyServiceExternalIPs" in [p.strip() for p in plugins]:
                                check_passed = True
                                break
                        elif arg == "--enable-admission-plugins" and i + 1 < len(args):
                            plugins = args[i + 1].split(",")
                            if "DenyServiceExternalIPs" in [p.strip() for p in plugins]:
                                check_passed = True
                                break
                    if check_passed:
                        break

                result = CheckResult(
                    check_id="apiserver_deny_service_external_ips",
                    check_name="Ensure that the DenyServiceExternalIPs is set",
                    status=CheckStatus.PASS if check_passed else CheckStatus.FAIL,
                    status_extended=(
                        f"DenyServiceExternalIPs admission controller is enabled in pod {pod.metadata.name}."
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
                        "Enable the DenyServiceExternalIPs admission controller by setting the '--enable-admission-plugins=DenyServiceExternalIPs' argument in the kube-apiserver configuration."
                    ]
                findings.append(result)

        except Exception as e:
            findings.append(CheckResult(
                check_id="apiserver_deny_service_external_ips",
                check_name="Ensure that the DenyServiceExternalIPs is set",
                status=CheckStatus.ERROR,
                status_extended=f"Error checking apiserver_deny_service_external_ips: {str(e)}",
                resource_id="unknown",
                resource_name="unknown",
                resource_type="Pod",
                severity=CheckSeverity.MEDIUM
            ))

        return findings

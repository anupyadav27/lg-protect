"""
Ensure that the --etcd-cafile argument is set as appropriate

This check ensures that the Kubernetes API server is configured with the --etcd-cafile argument, specifying the Certificate Authority file for etcd client connections. This setting is important for secure communication with etcd and ensures that the API server connects to etcd with an SSL Certificate Authority file.
"""

from typing import List
from kubernetes import client
from kubernetes_checks.base import KubernetesCheckBase
from utility.base_reporting import CheckResult, CheckStatus, CheckSeverity

class apiserver_etcd_cafile_set(KubernetesCheckBase):
    """Ensure that the --etcd-cafile argument is set as appropriate"""

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
                        # Handle --etcd-cafile=/path/to/ca and --etcd-cafile /path/to/ca
                        if arg.startswith("--etcd-cafile="):
                            ca_path = arg.split("=", 1)[1]
                            if ca_path:
                                check_passed = True
                                break
                        elif arg == "--etcd-cafile" and i + 1 < len(args):
                            ca_path = args[i + 1]
                            if ca_path:
                                check_passed = True
                                break
                    if check_passed:
                        break

                result = CheckResult(
                    check_id="apiserver_etcd_cafile_set",
                    check_name="Ensure that the --etcd-cafile argument is set as appropriate",
                    status=CheckStatus.PASS if check_passed else CheckStatus.FAIL,
                    status_extended=(
                        f"etcd CA file is set appropriately in pod {pod.metadata.name}."
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
                        "Ensure etcd connections from the API server are secured using the appropriate CA file."
                    ]
                findings.append(result)

        except Exception as e:
            findings.append(CheckResult(
                check_id="apiserver_etcd_cafile_set",
                check_name="Ensure that the --etcd-cafile argument is set as appropriate",
                status=CheckStatus.ERROR,
                status_extended=f"Error checking apiserver_etcd_cafile_set: {str(e)}",
                resource_id="unknown",
                resource_name="unknown",
                resource_type="Pod",
                severity=CheckSeverity.HIGH
            ))

        return findings

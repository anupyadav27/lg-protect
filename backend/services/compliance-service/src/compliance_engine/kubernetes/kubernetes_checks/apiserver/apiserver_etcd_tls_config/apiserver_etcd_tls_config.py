"""
Ensure that the --etcd-certfile and --etcd-keyfile arguments are set as appropriate

This check ensures that the Kubernetes API server is configured with TLS encryption for etcd client connections, using --etcd-certfile and --etcd-keyfile arguments. Setting up TLS for etcd is crucial for securing the sensitive data stored in etcd as it's the primary datastore for Kubernetes.
"""

from typing import List
from kubernetes import client
from kubernetes_checks.base import KubernetesCheckBase
from utility.base_reporting import CheckResult, CheckStatus, CheckSeverity

class apiserver_etcd_tls_config(KubernetesCheckBase):
    """Ensure that the --etcd-certfile and --etcd-keyfile arguments are set as appropriate"""

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
                    certfile_set = False
                    keyfile_set = False
                    for i, arg in enumerate(args):
                        # Handle --etcd-certfile and --etcd-keyfile (both = and space)
                        if arg.startswith("--etcd-certfile="):
                            certfile_path = arg.split("=", 1)[1]
                            if certfile_path:
                                certfile_set = True
                        elif arg == "--etcd-certfile" and i + 1 < len(args):
                            certfile_path = args[i + 1]
                            if certfile_path:
                                certfile_set = True
                        if arg.startswith("--etcd-keyfile="):
                            keyfile_path = arg.split("=", 1)[1]
                            if keyfile_path:
                                keyfile_set = True
                        elif arg == "--etcd-keyfile" and i + 1 < len(args):
                            keyfile_path = args[i + 1]
                            if keyfile_path:
                                keyfile_set = True
                    if certfile_set and keyfile_set:
                        check_passed = True
                        break

                result = CheckResult(
                    check_id="apiserver_etcd_tls_config",
                    check_name="Ensure that the --etcd-certfile and --etcd-keyfile arguments are set as appropriate",
                    status=CheckStatus.PASS if check_passed else CheckStatus.FAIL,
                    status_extended=(
                        f"TLS configuration for etcd is set appropriately in pod {pod.metadata.name}."
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
                        "Enable TLS encryption for etcd client connections to secure sensitive data."
                    ]
                findings.append(result)

        except Exception as e:
            findings.append(CheckResult(
                check_id="apiserver_etcd_tls_config",
                check_name="Ensure that the --etcd-certfile and --etcd-keyfile arguments are set as appropriate",
                status=CheckStatus.ERROR,
                status_extended=f"Error checking apiserver_etcd_tls_config: {str(e)}",
                resource_id="unknown",
                resource_name="unknown",
                resource_type="Pod",
                severity=CheckSeverity.HIGH
            ))

        return findings

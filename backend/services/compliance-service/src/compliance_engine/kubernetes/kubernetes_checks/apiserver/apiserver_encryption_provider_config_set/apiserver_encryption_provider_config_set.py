"""
Ensure that the --encryption-provider-config argument is set as appropriate

This check ensures that the Kubernetes API server is configured with the --encryption-provider-config argument to encrypt sensitive data at rest in the etcd key-value store. Encrypting data at rest prevents potential unauthorized disclosures and ensures that the sensitive data is secure.
"""

from typing import List
from kubernetes import client
from kubernetes_checks.base import KubernetesCheckBase
from utility.base_reporting import CheckResult, CheckStatus, CheckSeverity

class apiserver_encryption_provider_config_set(KubernetesCheckBase):
    """Ensure that the --encryption-provider-config argument is set as appropriate"""

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
                        # Handle --encryption-provider-config=/path and --encryption-provider-config /path
                        if arg.startswith("--encryption-provider-config="):
                            config_path = arg.split("=", 1)[1]
                            if config_path:
                                check_passed = True
                                break
                        elif arg == "--encryption-provider-config" and i + 1 < len(args):
                            config_path = args[i + 1]
                            if config_path:
                                check_passed = True
                                break
                    if check_passed:
                        break

                result = CheckResult(
                    check_id="apiserver_encryption_provider_config_set",
                    check_name="Ensure that the --encryption-provider-config argument is set as appropriate",
                    status=CheckStatus.PASS if check_passed else CheckStatus.FAIL,
                    status_extended=(
                        f"Encryption provider config is set appropriately in pod {pod.metadata.name}."
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
                        "Configure and enable encryption for data at rest in etcd using a suitable EncryptionConfig file."
                    ]
                findings.append(result)

        except Exception as e:
            findings.append(CheckResult(
                check_id="apiserver_encryption_provider_config_set",
                check_name="Ensure that the --encryption-provider-config argument is set as appropriate",
                status=CheckStatus.ERROR,
                status_extended=f"Error checking apiserver_encryption_provider_config_set: {str(e)}",
                resource_id="unknown",
                resource_name="unknown",
                resource_type="Pod",
                severity=CheckSeverity.HIGH
            ))

        return findings

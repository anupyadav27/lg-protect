"""
Ensure that the --service-account-key-file argument is set as appropriate

This check ensures that the Kubernetes API server is configured with a --service-account-key-file argument, specifying the public key file for service account verification. A separate key pair for service accounts enhances security by enabling key rotation and ensuring service account tokens are verified with a specific public key.
"""

from typing import List
from kubernetes import client
from kubernetes_checks.base import KubernetesCheckBase
from utility.base_reporting import CheckResult, CheckStatus, CheckSeverity

class apiserver_service_account_key_file_set(KubernetesCheckBase):
    """Ensure that the --service-account-key-file argument is set as appropriate"""

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
                        # Handle --service-account-key-file=/path and --service-account-key-file /path
                        if arg.startswith("--service-account-key-file="):
                            key_path = arg.split("=", 1)[1]
                            if key_path:
                                check_passed = True
                                break
                        elif arg == "--service-account-key-file" and i + 1 < len(args):
                            key_path = args[i + 1]
                            if key_path:
                                check_passed = True
                                break
                    if check_passed:
                        break

                result = CheckResult(
                    check_id="apiserver_service_account_key_file_set",
                    check_name="Ensure that the --service-account-key-file argument is set as appropriate",
                    status=CheckStatus.PASS if check_passed else CheckStatus.FAIL,
                    status_extended=(
                        f"Service account key file is set appropriately in pod {pod.metadata.name}."
                        if check_passed else
                        f"Service account key file is not set in pod {pod.metadata.name}."
                    ),
                    resource_id=pod.metadata.name,
                    resource_name=pod.metadata.name,
                    resource_type="Pod",
                    namespace="kube-system",
                    severity=CheckSeverity.HIGH
                )
                if not check_passed:
                    result.recommendations = [
                        "Specify a separate public key file for verifying service account tokens in the API server configuration."
                    ]
                findings.append(result)

        except Exception as e:
            findings.append(CheckResult(
                check_id="apiserver_service_account_key_file_set",
                check_name="Ensure that the --service-account-key-file argument is set as appropriate",
                status=CheckStatus.ERROR,
                status_extended=f"Error checking apiserver_service_account_key_file_set: {str(e)}",
                resource_id="unknown",
                resource_name="unknown",
                resource_type="Pod",
                severity=CheckSeverity.HIGH
            ))

        return findings

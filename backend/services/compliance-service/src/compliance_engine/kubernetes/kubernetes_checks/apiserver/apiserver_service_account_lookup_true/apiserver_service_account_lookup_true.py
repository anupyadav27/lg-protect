"""
Ensure that the --service-account-lookup argument is set to true

This check ensures that the Kubernetes API server is configured with --service-account-lookup set to true. This setting validates the service account associated with each request, ensuring that the service account token is not only valid but also currently exists.
"""

from typing import List
from kubernetes import client
from kubernetes_checks.base import KubernetesCheckBase
from utility.base_reporting import CheckResult, CheckStatus, CheckSeverity

class apiserver_service_account_lookup_true(KubernetesCheckBase):
    """Ensure that the --service-account-lookup argument is set to true"""

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
                        # Handle --service-account-lookup=true and --service-account-lookup true
                        if arg == "--service-account-lookup=true":
                            check_passed = True
                            break
                        elif arg == "--service-account-lookup" and i + 1 < len(args):
                            if args[i + 1].lower() == "true":
                                check_passed = True
                                break
                    if check_passed:
                        break

                result = CheckResult(
                    check_id="apiserver_service_account_lookup_true",
                    check_name="Ensure that the --service-account-lookup argument is set to true",
                    status=CheckStatus.PASS if check_passed else CheckStatus.FAIL,
                    status_extended=(
                        f"Service account lookup is set to true in pod {pod.metadata.name}."
                        if check_passed else
                        f"Service account lookup is not set to true in pod {pod.metadata.name}."
                    ),
                    resource_id=pod.metadata.name,
                    resource_name=pod.metadata.name,
                    resource_type="Pod",
                    namespace="kube-system",
                    severity=CheckSeverity.HIGH
                )
                if not check_passed:
                    result.recommendations = [
                        "Enable service account lookup in the API server to ensure that only existing service accounts are used for authentication."
                    ]
                findings.append(result)

        except Exception as e:
            findings.append(CheckResult(
                check_id="apiserver_service_account_lookup_true",
                check_name="Ensure that the --service-account-lookup argument is set to true",
                status=CheckStatus.ERROR,
                status_extended=f"Error checking apiserver_service_account_lookup_true: {str(e)}",
                resource_id="unknown",
                resource_name="unknown",
                resource_type="Pod",
                severity=CheckSeverity.HIGH
            ))

        return findings

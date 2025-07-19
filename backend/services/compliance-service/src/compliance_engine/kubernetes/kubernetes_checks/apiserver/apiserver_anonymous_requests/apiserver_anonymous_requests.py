from typing import List
from kubernetes import client
from kubernetes_checks.base import KubernetesCheckBase
from utility.base_reporting import CheckResult, CheckStatus, CheckSeverity

class apiserver_anonymous_requests(KubernetesCheckBase):
    def execute(self) -> List[CheckResult]:
        findings = []
        try:
            v1_api = client.CoreV1Api(self.provider)
            api_server_pods = v1_api.list_namespaced_pod(
                namespace="kube-system",
                label_selector="component=kube-apiserver"
            )
            for pod in api_server_pods.items:
                result = CheckResult(
                    check_id="apiserver_anonymous_requests",
                    check_name="API Server Anonymous Requests",
                    status=CheckStatus.PASS,
                    status_extended=f"API Server does not have anonymous-auth enabled in pod {pod.metadata.name}.",
                    resource_id=pod.metadata.name,
                    resource_name=pod.metadata.name,
                    resource_type="Pod",
                    namespace="kube-system",
                    severity=CheckSeverity.HIGH
                )
                anonymous_auth_enabled = False
                for container in pod.spec.containers:
                    for command in container.args or []:
                        if "--anonymous-auth=true" in command:
                            anonymous_auth_enabled = True
                            break
                if anonymous_auth_enabled:
                    result.status = CheckStatus.FAIL
                    result.status_extended = f"API Server has anonymous-auth enabled in pod {pod.metadata.name}."
                    result.recommendations = [
                        "Set --anonymous-auth=false in the API server configuration."
                    ]
                findings.append(result)
        except Exception as e:
            findings.append(CheckResult(
                check_id="apiserver_anonymous_requests",
                check_name="API Server Anonymous Requests",
                status=CheckStatus.ERROR,
                status_extended=f"Error checking anonymous-auth: {str(e)}",
                resource_id="unknown",
                resource_name="unknown",
                resource_type="Pod",
                severity=CheckSeverity.HIGH
            ))
        return findings

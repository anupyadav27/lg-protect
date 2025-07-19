"""
API Server Always Pull Images Plugin Check

This check verifies that the AlwaysPullImages admission control plugin is enabled in the Kubernetes API server.
"""

from typing import List
from kubernetes import client
from kubernetes.client.rest import ApiException
from kubernetes_checks.base import KubernetesCheckBase
from utility.base_reporting import CheckResult, CheckStatus, CheckSeverity


class apiserver_always_pull_images_plugin(KubernetesCheckBase):
    """Check if AlwaysPullImages admission control plugin is enabled."""
    
    def execute(self) -> List[CheckResult]:
        findings = []
        try:
            # Get API server pods from kube-system namespace
            v1_api = client.CoreV1Api(self.provider)
            api_server_pods = v1_api.list_namespaced_pod(
                namespace="kube-system",
                label_selector="component=kube-apiserver"
            )
            
            for pod in api_server_pods.items:
                result = CheckResult(
                    check_id="apiserver_always_pull_images_plugin",
                    check_name="API Server Always Pull Images Plugin",
                    status=CheckStatus.PASS,
                    status_extended=f"AlwaysPullImages admission control plugin is set in pod {pod.metadata.name}.",
                    resource_id=pod.metadata.name,
                    resource_name=pod.metadata.name,
                    resource_type="Pod",
                    namespace="kube-system",
                    severity=CheckSeverity.MEDIUM
                )
                
                plugin_set = False
                for container in pod.spec.containers:
                    for command in container.args or []:
                        if command.startswith("--enable-admission-plugins"):
                            if "AlwaysPullImages" in command:
                                plugin_set = True
                                break
                    if not plugin_set:
                        break
                
                if not plugin_set:
                    result.status = CheckStatus.FAIL
                    result.status_extended = f"AlwaysPullImages admission control plugin is not set in pod {pod.metadata.name}."
                    result.recommendations = [
                        "Enable the AlwaysPullImages admission control plugin",
                        "Add 'AlwaysPullImages' to the --enable-admission-plugins flag"
                    ]
                
                findings.append(result)
                
        except Exception as e:
            findings.append(CheckResult(
                check_id="apiserver_always_pull_images_plugin",
                check_name="API Server Always Pull Images Plugin",
                status=CheckStatus.ERROR,
                status_extended=f"Error checking AlwaysPullImages plugin: {str(e)}",
                resource_id="unknown",
                resource_name="unknown",
                resource_type="Pod",
                severity=CheckSeverity.HIGH
            ))
        
        return findings

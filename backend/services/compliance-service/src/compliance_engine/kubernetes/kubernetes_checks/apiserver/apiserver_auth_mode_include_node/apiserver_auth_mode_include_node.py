"""
Ensure that the --authorization-mode argument includes Node

This check ensures that the Kubernetes API server is configured to include 'Node' in its --authorization-mode argument. This mode restricts kubelets to only read objects associated with their nodes, enhancing security.
"""

from typing import List
from kubernetes import client
from kubernetes_checks.base import KubernetesCheckBase
from utility.base_reporting import CheckResult, CheckStatus, CheckSeverity


class apiserver_auth_mode_include_node(KubernetesCheckBase):
    """Ensure that the --authorization-mode argument includes Node"""
    
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
                    check_id="apiserver_auth_mode_include_node",
                    check_name="Ensure that the --authorization-mode argument includes Node",
                    status=CheckStatus.PASS,
                    status_extended=f"Configuration is properly set in pod {pod.metadata.name}.",
                    resource_id=pod.metadata.name,
                    resource_name=pod.metadata.name,
                    resource_type="Pod",
                    namespace="kube-system",
                    severity=CheckSeverity.MEDIUM
                )
                
                # Check logic
                check_passed = True
f"API Server authorization mode includes Node in pod {pod.metadata.name}."
)
                node_auth_mode_set = False
for container in pod.spec.containers:
                node_auth_mode_set = False
for command in container.args or []:
                if command.startswith("--authorization-mode"):
if "Node" in (command.split("=")[1]):
                                                check_passed = True
                                                break
                                if not check_passed:
                                                break
                                if not check_passed:
                # TODO: Add final check logic to set check_passed = False if needed

                
                if not check_passed:
                    result.status = CheckStatus.FAIL
                    result.status_extended = f"Configuration is not properly set in pod {pod.metadata.name}."
                    result.recommendations = [
                        "Configure the API server to use Node authorization mode along with other modes like RBAC to restrict kubelet access to the necessary resources."
                    ]
                
                findings.append(result)
                
        except Exception as e:
            findings.append(CheckResult(
                check_id="apiserver_auth_mode_include_node",
                check_name="Ensure that the --authorization-mode argument includes Node",
                status=CheckStatus.ERROR,
                status_extended=f"Error checking apiserver_auth_mode_include_node: {str(e)}",
                resource_id="unknown",
                resource_name="unknown",
                resource_type="Pod",
                severity=CheckSeverity.MEDIUM
            ))
        
        return findings

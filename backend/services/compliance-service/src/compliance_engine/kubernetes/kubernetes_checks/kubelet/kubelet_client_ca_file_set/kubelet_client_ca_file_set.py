from typing import List
from kubernetes import client
from kubernetes_checks.base import KubernetesCheckBase
from utility.base_reporting import CheckResult, CheckStatus, CheckSeverity

class kubelet_client_ca_file_set(KubernetesCheckBase):
    def execute(self) -> List[CheckResult]:
        findings = []
        try:
            v1_api = client.CoreV1Api(self.provider)
            kubelet_pods = v1_api.list_namespaced_pod(
                namespace="kube-system",
                label_selector="component=kubelet"
            )
            
            for pod in kubelet_pods.items:
                result = CheckResult(
                    check_id="kubelet_client_ca_file_set",
                    check_name="Kubelet Client CA File Set",
                    status=CheckStatus.PASS,
                    status_extended=f"Kubelet has the client CA file configured appropriately in pod {pod.metadata.name}.",
                    resource_id=pod.metadata.name,
                    resource_name=pod.metadata.name,
                    resource_type="Pod",
                    namespace="kube-system",
                    severity=CheckSeverity.HIGH
                )
                
                authentication_found = False
                client_ca_file_found = False
                
                for container in pod.spec.containers:
                    # Check container arguments
                    for arg in container.args or []:
                        if "--client-ca-file=" in arg:
                            authentication_found = True
                            client_ca_file_found = True
                            break
                    
                    # Check container commands
                    for cmd in container.command or []:
                        if "--client-ca-file=" in cmd:
                            authentication_found = True
                            client_ca_file_found = True
                            break
                
                if not authentication_found:
                    result.status = CheckStatus.MANUAL
                    result.status_extended = f"Kubelet does not have the client-ca-file argument configured in pod {pod.metadata.name}, verify it in the node's arguments."
                elif not client_ca_file_found:
                    result.status = CheckStatus.FAIL
                    result.status_extended = f"Kubelet is missing the client CA file configuration in pod {pod.metadata.name}."
                
                findings.append(result)
                
        except Exception as e:
            result = CheckResult(
                check_id="kubelet_client_ca_file_set",
                check_name="Kubelet Client CA File Set",
                status=CheckStatus.ERROR,
                status_extended=f"Error checking kubelet client CA file configuration: {str(e)}",
                resource_id="",
                resource_name="",
                resource_type="Pod",
                namespace="kube-system",
                severity=CheckSeverity.HIGH
            )
            findings.append(result)
        
        return findings

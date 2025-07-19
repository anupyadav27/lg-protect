from typing import List
from kubernetes import client
from kubernetes_checks.base import KubernetesCheckBase
from utility.base_reporting import CheckResult, CheckStatus, CheckSeverity

class kubelet_disable_read_only_port(KubernetesCheckBase):
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
                    check_id="kubelet_disable_read_only_port",
                    check_name="Kubelet Disable Read Only Port",
                    status=CheckStatus.PASS,
                    status_extended=f"Kubelet has the read-only port disabled in pod {pod.metadata.name}.",
                    resource_id=pod.metadata.name,
                    resource_name=pod.metadata.name,
                    resource_type="Pod",
                    namespace="kube-system",
                    severity=CheckSeverity.HIGH
                )
                
                read_only_port_found = False
                read_only_port_disabled = False
                
                for container in pod.spec.containers:
                    # Check container arguments
                    for arg in container.args or []:
                        if "--read-only-port=" in arg:
                            read_only_port_found = True
                            if "--read-only-port=0" in arg:
                                read_only_port_disabled = True
                                break
                    
                    # Check container commands
                    for cmd in container.command or []:
                        if "--read-only-port=" in cmd:
                            read_only_port_found = True
                            if "--read-only-port=0" in cmd:
                                read_only_port_disabled = True
                                break
                
                if not read_only_port_found:
                    result.status = CheckStatus.MANUAL
                    result.status_extended = f"Kubelet does not have the read-only-port argument configured in pod {pod.metadata.name}, verify it in the node's arguments."
                elif not read_only_port_disabled:
                    result.status = CheckStatus.FAIL
                    result.status_extended = f"Kubelet has the read-only port enabled in pod {pod.metadata.name}."
                
                findings.append(result)
                
        except Exception as e:
            result = CheckResult(
                check_id="kubelet_disable_read_only_port",
                check_name="Kubelet Disable Read Only Port",
                status=CheckStatus.ERROR,
                status_extended=f"Error checking kubelet read-only port configuration: {str(e)}",
                resource_id="",
                resource_name="",
                resource_type="Pod",
                namespace="kube-system",
                severity=CheckSeverity.HIGH
            )
            findings.append(result)
        
        return findings

from typing import List
from kubernetes import client
from kubernetes_checks.base import KubernetesCheckBase
from utility.base_reporting import CheckResult, CheckStatus, CheckSeverity

class kubelet_rotate_certificates(KubernetesCheckBase):
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
                    check_id="kubelet_rotate_certificates",
                    check_name="Kubelet Rotate Certificates",
                    status=CheckStatus.PASS,
                    status_extended=f"Kubelet has certificate rotation enabled in pod {pod.metadata.name}.",
                    resource_id=pod.metadata.name,
                    resource_name=pod.metadata.name,
                    resource_type="Pod",
                    namespace="kube-system",
                    severity=CheckSeverity.HIGH
                )
                
                rotate_certificates_found = False
                rotate_certificates_enabled = False
                
                for container in pod.spec.containers:
                    # Check container arguments
                    for arg in container.args or []:
                        if "--rotate-certificates=" in arg:
                            rotate_certificates_found = True
                            if "--rotate-certificates=true" in arg:
                                rotate_certificates_enabled = True
                                break
                    
                    # Check container commands
                    for cmd in container.command or []:
                        if "--rotate-certificates=" in cmd:
                            rotate_certificates_found = True
                            if "--rotate-certificates=true" in cmd:
                                rotate_certificates_enabled = True
                                break
                
                if not rotate_certificates_found:
                    result.status = CheckStatus.MANUAL
                    result.status_extended = f"Kubelet does not have the rotate-certificates argument configured in pod {pod.metadata.name}, verify it in the node's arguments."
                elif not rotate_certificates_enabled:
                    result.status = CheckStatus.FAIL
                    result.status_extended = f"Kubelet has client certificate rotation disabled in pod {pod.metadata.name}."
                
                findings.append(result)
                
        except Exception as e:
            result = CheckResult(
                check_id="kubelet_rotate_certificates",
                check_name="Kubelet Rotate Certificates",
                status=CheckStatus.ERROR,
                status_extended=f"Error checking kubelet certificate rotation configuration: {str(e)}",
                resource_id="",
                resource_name="",
                resource_type="Pod",
                namespace="kube-system",
                severity=CheckSeverity.HIGH
            )
            findings.append(result)
        
        return findings

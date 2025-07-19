from typing import List
from kubernetes import client
from kubernetes_checks.base import KubernetesCheckBase
from utility.base_reporting import CheckResult, CheckStatus, CheckSeverity

class kubelet_authorization_mode(KubernetesCheckBase):
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
                    check_id="kubelet_authorization_mode",
                    check_name="Kubelet Authorization Mode",
                    status=CheckStatus.PASS,
                    status_extended=f"Kubelet is not using 'AlwaysAllow' as the authorization mode in pod {pod.metadata.name}.",
                    resource_id=pod.metadata.name,
                    resource_name=pod.metadata.name,
                    resource_type="Pod",
                    namespace="kube-system",
                    severity=CheckSeverity.HIGH
                )
                
                authorization_mode_found = False
                always_allow_found = False
                
                for container in pod.spec.containers:
                    # Check container arguments
                    for arg in container.args or []:
                        if "--authorization-mode=" in arg:
                            authorization_mode_found = True
                            if "AlwaysAllow" in arg:
                                always_allow_found = True
                                break
                    
                    # Check container commands
                    for cmd in container.command or []:
                        if "--authorization-mode=" in cmd:
                            authorization_mode_found = True
                            if "AlwaysAllow" in cmd:
                                always_allow_found = True
                                break
                
                if not authorization_mode_found:
                    result.status = CheckStatus.MANUAL
                    result.status_extended = f"Kubelet does not have the authorization-mode argument configured in pod {pod.metadata.name}, verify it in the node's arguments."
                elif always_allow_found:
                    result.status = CheckStatus.FAIL
                    result.status_extended = f"Kubelet is incorrectly set to use 'AlwaysAllow' as the authorization mode in pod {pod.metadata.name}."
                
                findings.append(result)
                
        except Exception as e:
            result = CheckResult(
                check_id="kubelet_authorization_mode",
                check_name="Kubelet Authorization Mode",
                status=CheckStatus.ERROR,
                status_extended=f"Error checking kubelet authorization mode: {str(e)}",
                resource_id="",
                resource_name="",
                resource_type="Pod",
                namespace="kube-system",
                severity=CheckSeverity.HIGH
            )
            findings.append(result)
        
        return findings

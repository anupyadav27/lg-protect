from typing import List
from kubernetes import client
from kubernetes_checks.base import KubernetesCheckBase
from utility.base_reporting import CheckResult, CheckStatus, CheckSeverity

class kubelet_disable_anonymous_auth(KubernetesCheckBase):
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
                    check_id="kubelet_disable_anonymous_auth",
                    check_name="Kubelet Disable Anonymous Auth",
                    status=CheckStatus.PASS,
                    status_extended=f"Kubelet does not have anonymous access enabled in pod {pod.metadata.name}.",
                    resource_id=pod.metadata.name,
                    resource_name=pod.metadata.name,
                    resource_type="Pod",
                    namespace="kube-system",
                    severity=CheckSeverity.HIGH
                )
                
                anonymous_auth_enabled = False
                
                for container in pod.spec.containers:
                    # Check container arguments
                    for arg in container.args or []:
                        if "--anonymous-auth=true" in arg:
                            anonymous_auth_enabled = True
                            break
                    
                    # Check container commands
                    for cmd in container.command or []:
                        if "--anonymous-auth=true" in cmd:
                            anonymous_auth_enabled = True
                            break
                
                if anonymous_auth_enabled:
                    result.status = CheckStatus.FAIL
                    result.status_extended = f"Kubelet has anonymous access enabled in pod {pod.metadata.name}."
                
                findings.append(result)
                
        except Exception as e:
            result = CheckResult(
                check_id="kubelet_disable_anonymous_auth",
                check_name="Kubelet Disable Anonymous Auth",
                status=CheckStatus.ERROR,
                status_extended=f"Error checking kubelet anonymous authentication: {str(e)}",
                resource_id="",
                resource_name="",
                resource_type="Pod",
                namespace="kube-system",
                severity=CheckSeverity.HIGH
            )
            findings.append(result)
        
        return findings

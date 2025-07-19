from typing import List
from kubernetes import client
from kubernetes_checks.base import KubernetesCheckBase
from utility.base_reporting import CheckResult, CheckStatus, CheckSeverity

class kubelet_manage_iptables(KubernetesCheckBase):
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
                    check_id="kubelet_manage_iptables",
                    check_name="Kubelet Manage Iptables",
                    status=CheckStatus.PASS,
                    status_extended=f"Kubelet is configured to manage iptables in pod {pod.metadata.name}.",
                    resource_id=pod.metadata.name,
                    resource_name=pod.metadata.name,
                    resource_type="Pod",
                    namespace="kube-system",
                    severity=CheckSeverity.HIGH
                )
                
                iptables_found = False
                iptables_enabled = False
                
                for container in pod.spec.containers:
                    # Check container arguments
                    for arg in container.args or []:
                        if "--make-iptables-util-chains=" in arg:
                            iptables_found = True
                            if "--make-iptables-util-chains=true" in arg:
                                iptables_enabled = True
                                break
                    
                    # Check container commands
                    for cmd in container.command or []:
                        if "--make-iptables-util-chains=" in cmd:
                            iptables_found = True
                            if "--make-iptables-util-chains=true" in cmd:
                                iptables_enabled = True
                                break
                
                if not iptables_found:
                    result.status = CheckStatus.MANUAL
                    result.status_extended = f"Kubelet does not have the make-iptables-util-chains argument configured in pod {pod.metadata.name}, verify it in the node's arguments."
                elif not iptables_enabled:
                    result.status = CheckStatus.FAIL
                    result.status_extended = f"Kubelet is not configured to manage iptables in pod {pod.metadata.name}."
                
                findings.append(result)
                
        except Exception as e:
            result = CheckResult(
                check_id="kubelet_manage_iptables",
                check_name="Kubelet Manage Iptables",
                status=CheckStatus.ERROR,
                status_extended=f"Error checking kubelet iptables management configuration: {str(e)}",
                resource_id="",
                resource_name="",
                resource_type="Pod",
                namespace="kube-system",
                severity=CheckSeverity.HIGH
            )
            findings.append(result)
        
        return findings

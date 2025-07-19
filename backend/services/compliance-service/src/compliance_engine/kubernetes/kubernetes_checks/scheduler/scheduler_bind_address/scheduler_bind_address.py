from typing import List
from kubernetes import client
from kubernetes_checks.base import KubernetesCheckBase
from utility.base_reporting import CheckResult, CheckStatus, CheckSeverity

class scheduler_bind_address(KubernetesCheckBase):
    def execute(self) -> List[CheckResult]:
        findings = []
        try:
            v1_api = client.CoreV1Api(self.provider)
            scheduler_pods = v1_api.list_namespaced_pod(
                namespace="kube-system",
                label_selector="component=kube-scheduler"
            )
            
            for pod in scheduler_pods.items:
                result = CheckResult(
                    check_id="scheduler_bind_address",
                    check_name="Scheduler Bind Address",
                    status=CheckStatus.PASS,
                    status_extended=f"Scheduler is bound to the loopback address in pod {pod.metadata.name}.",
                    resource_id=pod.metadata.name,
                    resource_name=pod.metadata.name,
                    resource_type="Pod",
                    namespace="kube-system",
                    severity=CheckSeverity.HIGH
                )
                
                bind_address_found = False
                
                for container in pod.spec.containers:
                    # Check container arguments
                    for arg in container.args or []:
                        if "--bind-address=127.0.0.1" in arg:
                            bind_address_found = True
                            break
                    
                    # Check container commands
                    for cmd in container.command or []:
                        if "--bind-address=127.0.0.1" in cmd:
                            bind_address_found = True
                            break
                
                if not bind_address_found:
                    result.status = CheckStatus.FAIL
                    result.status_extended = f"Scheduler is not bound to the loopback address in pod {pod.metadata.name}."
                
                findings.append(result)
                
        except Exception as e:
            result = CheckResult(
                check_id="scheduler_bind_address",
                check_name="Scheduler Bind Address",
                status=CheckStatus.ERROR,
                status_extended=f"Error checking scheduler bind address: {str(e)}",
                resource_id="",
                resource_name="",
                resource_type="Pod",
                namespace="kube-system",
                severity=CheckSeverity.HIGH
            )
            findings.append(result)
        
        return findings

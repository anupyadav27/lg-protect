from typing import List
from kubernetes import client
from kubernetes_checks.base import KubernetesCheckBase
from utility.base_reporting import CheckResult, CheckStatus, CheckSeverity

class scheduler_profiling(KubernetesCheckBase):
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
                    check_id="scheduler_profiling",
                    check_name="Scheduler Profiling",
                    status=CheckStatus.FAIL,
                    status_extended=f"Scheduler has profiling enabled in pod {pod.metadata.name}.",
                    resource_id=pod.metadata.name,
                    resource_name=pod.metadata.name,
                    resource_type="Pod",
                    namespace="kube-system",
                    severity=CheckSeverity.HIGH
                )
                
                profiling_disabled = False
                
                for container in pod.spec.containers:
                    # Check container arguments
                    for arg in container.args or []:
                        if "--profiling=false" in arg:
                            profiling_disabled = True
                            break
                    
                    # Check container commands
                    for cmd in container.command or []:
                        if "--profiling=false" in cmd:
                            profiling_disabled = True
                            break
                
                if profiling_disabled:
                    result.status = CheckStatus.PASS
                    result.status_extended = f"Scheduler does not have profiling enabled in pod {pod.metadata.name}."
                
                findings.append(result)
                
        except Exception as e:
            result = CheckResult(
                check_id="scheduler_profiling",
                check_name="Scheduler Profiling",
                status=CheckStatus.ERROR,
                status_extended=f"Error checking scheduler profiling: {str(e)}",
                resource_id="",
                resource_name="",
                resource_type="Pod",
                namespace="kube-system",
                severity=CheckSeverity.HIGH
            )
            findings.append(result)
        
        return findings

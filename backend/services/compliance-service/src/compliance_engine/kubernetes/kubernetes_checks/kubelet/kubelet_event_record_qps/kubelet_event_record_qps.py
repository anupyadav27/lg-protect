from typing import List
from kubernetes import client
from kubernetes_checks.base import KubernetesCheckBase
from utility.base_reporting import CheckResult, CheckStatus, CheckSeverity

class kubelet_event_record_qps(KubernetesCheckBase):
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
                    check_id="kubelet_event_record_qps",
                    check_name="Kubelet Event Record QPS",
                    status=CheckStatus.PASS,
                    status_extended=f"Kubelet has an appropriate eventRecordQPS setting in pod {pod.metadata.name}.",
                    resource_id=pod.metadata.name,
                    resource_name=pod.metadata.name,
                    resource_type="Pod",
                    namespace="kube-system",
                    severity=CheckSeverity.HIGH
                )
                
                event_record_qps_found = False
                event_record_qps_valid = False
                
                for container in pod.spec.containers:
                    # Check container arguments
                    for arg in container.args or []:
                        if "--event-record-qps=" in arg:
                            event_record_qps_found = True
                            # Extract the value and check if it's greater than 0
                            try:
                                value = arg.split("=")[1]
                                if value.isdigit() and int(value) > 0:
                                    event_record_qps_valid = True
                                    break
                            except (IndexError, ValueError):
                                pass
                    
                    # Check container commands
                    for cmd in container.command or []:
                        if "--event-record-qps=" in cmd:
                            event_record_qps_found = True
                            # Extract the value and check if it's greater than 0
                            try:
                                value = cmd.split("=")[1]
                                if value.isdigit() and int(value) > 0:
                                    event_record_qps_valid = True
                                    break
                            except (IndexError, ValueError):
                                pass
                
                if not event_record_qps_found:
                    result.status = CheckStatus.MANUAL
                    result.status_extended = f"Kubelet does not have the event-record-qps argument configured in pod {pod.metadata.name}, verify it in the node's arguments."
                elif not event_record_qps_valid:
                    result.status = CheckStatus.FAIL
                    result.status_extended = f"Kubelet has eventRecordQPS set to 0 that may lead to DoS conditions in pod {pod.metadata.name}."
                
                findings.append(result)
                
        except Exception as e:
            result = CheckResult(
                check_id="kubelet_event_record_qps",
                check_name="Kubelet Event Record QPS",
                status=CheckStatus.ERROR,
                status_extended=f"Error checking kubelet event record QPS configuration: {str(e)}",
                resource_id="",
                resource_name="",
                resource_type="Pod",
                namespace="kube-system",
                severity=CheckSeverity.HIGH
            )
            findings.append(result)
        
        return findings

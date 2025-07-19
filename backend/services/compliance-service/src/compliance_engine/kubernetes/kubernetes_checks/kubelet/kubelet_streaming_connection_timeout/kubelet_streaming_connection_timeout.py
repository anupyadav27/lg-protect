from typing import List
from kubernetes import client
from kubernetes_checks.base import KubernetesCheckBase
from utility.base_reporting import CheckResult, CheckStatus, CheckSeverity

class kubelet_streaming_connection_timeout(KubernetesCheckBase):
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
                    check_id="kubelet_streaming_connection_timeout",
                    check_name="Kubelet Streaming Connection Timeout",
                    status=CheckStatus.PASS,
                    status_extended=f"Kubelet is configured with a non-zero streaming connection idle timeout in pod {pod.metadata.name}.",
                    resource_id=pod.metadata.name,
                    resource_name=pod.metadata.name,
                    resource_type="Pod",
                    namespace="kube-system",
                    severity=CheckSeverity.HIGH
                )
                
                streaming_timeout_found = False
                streaming_timeout_valid = False
                
                for container in pod.spec.containers:
                    # Check container arguments
                    for arg in container.args or []:
                        if "--streaming-connection-idle-timeout=" in arg:
                            streaming_timeout_found = True
                            # Extract the value and check if it's not 0
                            try:
                                value = arg.split("=")[1]
                                if value.isdigit() and int(value) != 0:
                                    streaming_timeout_valid = True
                                    break
                            except (IndexError, ValueError):
                                pass
                    
                    # Check container commands
                    for cmd in container.command or []:
                        if "--streaming-connection-idle-timeout=" in cmd:
                            streaming_timeout_found = True
                            # Extract the value and check if it's not 0
                            try:
                                value = cmd.split("=")[1]
                                if value.isdigit() and int(value) != 0:
                                    streaming_timeout_valid = True
                                    break
                            except (IndexError, ValueError):
                                pass
                
                if not streaming_timeout_found:
                    result.status = CheckStatus.MANUAL
                    result.status_extended = f"Kubelet does not have the streaming-connection-idle-timeout argument configured in pod {pod.metadata.name}, verify it in the node's arguments."
                elif not streaming_timeout_valid:
                    result.status = CheckStatus.FAIL
                    result.status_extended = f"Kubelet has a streaming connection idle timeout set to 0 in pod {pod.metadata.name}."
                
                findings.append(result)
                
        except Exception as e:
            result = CheckResult(
                check_id="kubelet_streaming_connection_timeout",
                check_name="Kubelet Streaming Connection Timeout",
                status=CheckStatus.ERROR,
                status_extended=f"Error checking kubelet streaming connection timeout configuration: {str(e)}",
                resource_id="",
                resource_name="",
                resource_type="Pod",
                namespace="kube-system",
                severity=CheckSeverity.HIGH
            )
            findings.append(result)
        
        return findings

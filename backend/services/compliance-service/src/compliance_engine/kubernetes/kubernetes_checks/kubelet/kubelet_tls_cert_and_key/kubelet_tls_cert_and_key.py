from typing import List
from kubernetes import client
from kubernetes_checks.base import KubernetesCheckBase
from utility.base_reporting import CheckResult, CheckStatus, CheckSeverity

class kubelet_tls_cert_and_key(KubernetesCheckBase):
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
                    check_id="kubelet_tls_cert_and_key",
                    check_name="Kubelet TLS Cert And Key",
                    status=CheckStatus.PASS,
                    status_extended=f"Kubelet has appropriate TLS certificate and private key configured in pod {pod.metadata.name}.",
                    resource_id=pod.metadata.name,
                    resource_name=pod.metadata.name,
                    resource_type="Pod",
                    namespace="kube-system",
                    severity=CheckSeverity.HIGH
                )
                
                tls_cert_found = False
                tls_key_found = False
                
                for container in pod.spec.containers:
                    # Check container arguments
                    for arg in container.args or []:
                        if "--tls-cert-file=" in arg:
                            tls_cert_found = True
                        if "--tls-private-key-file=" in arg:
                            tls_key_found = True
                    
                    # Check container commands
                    for cmd in container.command or []:
                        if "--tls-cert-file=" in cmd:
                            tls_cert_found = True
                        if "--tls-private-key-file=" in cmd:
                            tls_key_found = True
                
                if not tls_cert_found or not tls_key_found:
                    result.status = CheckStatus.FAIL
                    result.status_extended = f"Kubelet is missing TLS certificate and/or private key configuration in pod {pod.metadata.name}."
                
                findings.append(result)
                
        except Exception as e:
            result = CheckResult(
                check_id="kubelet_tls_cert_and_key",
                check_name="Kubelet TLS Cert And Key",
                status=CheckStatus.ERROR,
                status_extended=f"Error checking kubelet TLS certificate and key configuration: {str(e)}",
                resource_id="",
                resource_name="",
                resource_type="Pod",
                namespace="kube-system",
                severity=CheckSeverity.HIGH
            )
            findings.append(result)
        
        return findings

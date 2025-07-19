from typing import List
from kubernetes import client
from kubernetes_checks.base import KubernetesCheckBase
from utility.base_reporting import CheckResult, CheckStatus, CheckSeverity

default_kubelet_strong_ciphers = [
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_RSA_WITH_AES_128_GCM_SHA256",
]

class kubelet_strong_ciphers_only(KubernetesCheckBase):
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
                    check_id="kubelet_strong_ciphers_only",
                    check_name="Kubelet Strong Ciphers Only",
                    status=CheckStatus.PASS,
                    status_extended=f"Kubelet is configured with strong cryptographic ciphers in pod {pod.metadata.name}.",
                    resource_id=pod.metadata.name,
                    resource_name=pod.metadata.name,
                    resource_type="Pod",
                    namespace="kube-system",
                    severity=CheckSeverity.HIGH
                )
                
                tls_ciphers_found = False
                tls_ciphers_valid = False
                
                for container in pod.spec.containers:
                    # Check container arguments
                    for arg in container.args or []:
                        if "--tls-cipher-suites=" in arg:
                            tls_ciphers_found = True
                            # Extract the cipher suites and check if they are strong
                            try:
                                ciphers_str = arg.split("=")[1]
                                ciphers = [c.strip() for c in ciphers_str.split(",")]
                                if all(cipher in default_kubelet_strong_ciphers for cipher in ciphers):
                                    tls_ciphers_valid = True
                                    break
                            except (IndexError, ValueError):
                                pass
                    
                    # Check container commands
                    for cmd in container.command or []:
                        if "--tls-cipher-suites=" in cmd:
                            tls_ciphers_found = True
                            # Extract the cipher suites and check if they are strong
                            try:
                                ciphers_str = cmd.split("=")[1]
                                ciphers = [c.strip() for c in ciphers_str.split(",")]
                                if all(cipher in default_kubelet_strong_ciphers for cipher in ciphers):
                                    tls_ciphers_valid = True
                                    break
                            except (IndexError, ValueError):
                                pass
                
                if not tls_ciphers_found:
                    result.status = CheckStatus.MANUAL
                    result.status_extended = f"Kubelet does not have the tls-cipher-suites argument configured in pod {pod.metadata.name}, verify it in the node's arguments."
                elif not tls_ciphers_valid:
                    result.status = CheckStatus.FAIL
                    result.status_extended = f"Kubelet is not using only strong cryptographic ciphers in pod {pod.metadata.name}."
                
                findings.append(result)
                
        except Exception as e:
            result = CheckResult(
                check_id="kubelet_strong_ciphers_only",
                check_name="Kubelet Strong Ciphers Only",
                status=CheckStatus.ERROR,
                status_extended=f"Error checking kubelet strong ciphers configuration: {str(e)}",
                resource_id="",
                resource_name="",
                resource_type="Pod",
                namespace="kube-system",
                severity=CheckSeverity.HIGH
            )
            findings.append(result)
        
        return findings

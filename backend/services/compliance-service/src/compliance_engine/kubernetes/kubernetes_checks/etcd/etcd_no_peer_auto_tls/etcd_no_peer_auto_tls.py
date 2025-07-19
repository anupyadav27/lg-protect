"""
Ensure that the --peer-auto-tls argument is not set to true for etcd

This check ensures that etcd is not configured to use self-signed certificates for peer-to-peer TLS connections, which can pose security risks. Using proper CA-signed certificates is recommended for production environments.
"""

from typing import List
from kubernetes import client
from kubernetes_checks.base import KubernetesCheckBase
from utility.base_reporting import CheckResult, CheckStatus, CheckSeverity

class etcd_no_peer_auto_tls(KubernetesCheckBase):
    """Ensure that the --peer-auto-tls argument is not set to true for etcd"""

    def execute(self) -> List[CheckResult]:
        findings = []
        try:
            # Get etcd pods from kube-system namespace
            v1_api = client.CoreV1Api(self.provider)
            etcd_pods = v1_api.list_namespaced_pod(
                namespace="kube-system",
                label_selector="component=etcd"
            )
            
            for pod in etcd_pods.items:
                check_passed = True
                
                # Check all containers in the etcd pod
                for container in pod.spec.containers or []:
                    args = container.args or []
                    command = container.command or []
                    
                    # Check for --peer-auto-tls=true in args
                    if "--peer-auto-tls=true" in args:
                        check_passed = False
                        break
                    
                    # Check for --peer-auto-tls in args (without value, defaults to true)
                    if "--peer-auto-tls" in args:
                        check_passed = False
                        break
                    
                    # Check in command as well
                    if "--peer-auto-tls=true" in command or "--peer-auto-tls" in command:
                        check_passed = False
                        break
                
                result = CheckResult(
                    check_id="etcd_no_peer_auto_tls",
                    check_name="Ensure that the --peer-auto-tls argument is not set to true for etcd",
                    status=CheckStatus.PASS if check_passed else CheckStatus.FAIL,
                    status_extended=(
                        f"Etcd is not using automatically generated self-signed certificates for peer TLS connections in pod {pod.metadata.name}."
                        if check_passed else
                        f"Etcd is using automatically generated self-signed certificates for peer TLS connections in pod {pod.metadata.name}."
                    ),
                    resource_id=pod.metadata.name,
                    resource_name=pod.metadata.name,
                    resource_type="Pod",
                    namespace="kube-system",
                    severity=CheckSeverity.HIGH
                )
                
                if not check_passed:
                    result.recommendations = [
                        "Disable peer-auto-tls in etcd configuration",
                        "Use proper CA-signed certificates for peer TLS",
                        "Configure etcd with valid peer certificates",
                        "Follow etcd security best practices"
                    ]
                
                findings.append(result)

        except Exception as e:
            findings.append(CheckResult(
                check_id="etcd_no_peer_auto_tls",
                check_name="Ensure that the --peer-auto-tls argument is not set to true for etcd",
                status=CheckStatus.ERROR,
                status_extended=f"Error checking etcd_no_peer_auto_tls: {str(e)}",
                resource_id="unknown",
                resource_name="unknown",
                resource_type="Pod",
                severity=CheckSeverity.HIGH
            ))

        return findings

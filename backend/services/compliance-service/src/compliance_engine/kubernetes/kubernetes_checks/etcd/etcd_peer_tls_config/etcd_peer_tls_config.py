"""
Ensure that etcd is configured with TLS for peer connections

This check ensures that etcd is configured with proper TLS certificates for peer-to-peer communication, which helps secure communication between etcd nodes.
"""

from typing import List
from kubernetes import client
from kubernetes_checks.base import KubernetesCheckBase
from utility.base_reporting import CheckResult, CheckStatus, CheckSeverity

class etcd_peer_tls_config(KubernetesCheckBase):
    """Ensure that etcd is configured with TLS for peer connections"""

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
                check_passed = False
                
                # Check all containers in the etcd pod
                for container in pod.spec.containers or []:
                    args = container.args or []
                    command = container.command or []
                    
                    # Check for both peer certificate and key files
                    has_peer_cert = False
                    has_peer_key = False
                    
                    # Check in args
                    for i, arg in enumerate(args):
                        if arg == "--peer-cert-file" and i + 1 < len(args):
                            has_peer_cert = True
                        elif arg == "--peer-key-file" and i + 1 < len(args):
                            has_peer_key = True
                    
                    # Check in command
                    for i, cmd in enumerate(command):
                        if cmd == "--peer-cert-file" and i + 1 < len(command):
                            has_peer_cert = True
                        elif cmd == "--peer-key-file" and i + 1 < len(command):
                            has_peer_key = True
                    
                    if has_peer_cert and has_peer_key:
                        check_passed = True
                        break
                
                result = CheckResult(
                    check_id="etcd_peer_tls_config",
                    check_name="Ensure that etcd is configured with TLS for peer connections",
                    status=CheckStatus.PASS if check_passed else CheckStatus.FAIL,
                    status_extended=(
                        f"Etcd is configured with TLS for peer connections in pod {pod.metadata.name}."
                        if check_passed else
                        f"Etcd does not have TLS configured for peer connections in pod {pod.metadata.name}."
                    ),
                    resource_id=pod.metadata.name,
                    resource_name=pod.metadata.name,
                    resource_type="Pod",
                    namespace="kube-system",
                    severity=CheckSeverity.HIGH
                )
                
                if not check_passed:
                    result.recommendations = [
                        "Configure TLS for etcd peer connections",
                        "Set --peer-cert-file and --peer-key-file in etcd configuration",
                        "Use proper certificates for peer communication",
                        "Follow etcd security best practices"
                    ]
                
                findings.append(result)

        except Exception as e:
            findings.append(CheckResult(
                check_id="etcd_peer_tls_config",
                check_name="Ensure that etcd is configured with TLS for peer connections",
                status=CheckStatus.ERROR,
                status_extended=f"Error checking etcd_peer_tls_config: {str(e)}",
                resource_id="unknown",
                resource_name="unknown",
                resource_type="Pod",
                severity=CheckSeverity.HIGH
            ))

        return findings

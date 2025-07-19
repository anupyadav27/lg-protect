"""
Ensure that etcd is configured with TLS encryption

This check ensures that etcd is configured with proper TLS certificates for client communication, which helps secure access to the etcd key-value store.
"""

from typing import List
from kubernetes import client
from kubernetes_checks.base import KubernetesCheckBase
from utility.base_reporting import CheckResult, CheckStatus, CheckSeverity

class etcd_tls_encryption(KubernetesCheckBase):
    """Ensure that etcd is configured with TLS encryption"""

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
                    
                    # Check for both certificate and key files
                    has_cert = False
                    has_key = False
                    
                    # Check in args
                    for i, arg in enumerate(args):
                        if arg == "--cert-file" and i + 1 < len(args):
                            has_cert = True
                        elif arg == "--key-file" and i + 1 < len(args):
                            has_key = True
                    
                    # Check in command
                    for i, cmd in enumerate(command):
                        if cmd == "--cert-file" and i + 1 < len(command):
                            has_cert = True
                        elif cmd == "--key-file" and i + 1 < len(command):
                            has_key = True
                    
                    if has_cert and has_key:
                        check_passed = True
                        break
                
                result = CheckResult(
                    check_id="etcd_tls_encryption",
                    check_name="Ensure that etcd is configured with TLS encryption",
                    status=CheckStatus.PASS if check_passed else CheckStatus.FAIL,
                    status_extended=(
                        f"Etcd has configured TLS encryption in pod {pod.metadata.name}."
                        if check_passed else
                        f"Etcd does not have TLS encryption configured in pod {pod.metadata.name}."
                    ),
                    resource_id=pod.metadata.name,
                    resource_name=pod.metadata.name,
                    resource_type="Pod",
                    namespace="kube-system",
                    severity=CheckSeverity.HIGH
                )
                
                if not check_passed:
                    result.recommendations = [
                        "Configure TLS encryption for etcd",
                        "Set --cert-file and --key-file in etcd configuration",
                        "Use proper certificates for client communication",
                        "Follow etcd security best practices"
                    ]
                
                findings.append(result)

        except Exception as e:
            findings.append(CheckResult(
                check_id="etcd_tls_encryption",
                check_name="Ensure that etcd is configured with TLS encryption",
                status=CheckStatus.ERROR,
                status_extended=f"Error checking etcd_tls_encryption: {str(e)}",
                resource_id="unknown",
                resource_name="unknown",
                resource_type="Pod",
                severity=CheckSeverity.HIGH
            ))

        return findings

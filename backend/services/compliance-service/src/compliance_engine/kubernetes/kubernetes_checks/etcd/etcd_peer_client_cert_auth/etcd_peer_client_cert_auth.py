"""
Ensure that the --peer-client-cert-auth argument is set to true for etcd

This check ensures that peer client certificate authentication is enabled for the etcd service, which helps secure peer-to-peer communication between etcd nodes.
"""

from typing import List
from kubernetes import client
from kubernetes_checks.base import KubernetesCheckBase
from utility.base_reporting import CheckResult, CheckStatus, CheckSeverity

class etcd_peer_client_cert_auth(KubernetesCheckBase):
    """Ensure that the --peer-client-cert-auth argument is set to true for etcd"""

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
                    
                    # Check for --peer-client-cert-auth=true in args
                    if "--peer-client-cert-auth=true" in args:
                        check_passed = True
                        break
                    
                    # Check for --peer-client-cert-auth in args (without value, defaults to true)
                    if "--peer-client-cert-auth" in args:
                        check_passed = True
                        break
                    
                    # Check in command as well
                    if "--peer-client-cert-auth=true" in command or "--peer-client-cert-auth" in command:
                        check_passed = True
                        break
                
                result = CheckResult(
                    check_id="etcd_peer_client_cert_auth",
                    check_name="Ensure that the --peer-client-cert-auth argument is set to true for etcd",
                    status=CheckStatus.PASS if check_passed else CheckStatus.FAIL,
                    status_extended=(
                        f"Etcd is configured for peer client certificate authentication in pod {pod.metadata.name}."
                        if check_passed else
                        f"Etcd does not have peer client certificate authentication configured in pod {pod.metadata.name}."
                    ),
                    resource_id=pod.metadata.name,
                    resource_name=pod.metadata.name,
                    resource_type="Pod",
                    namespace="kube-system",
                    severity=CheckSeverity.HIGH
                )
                
                if not check_passed:
                    result.recommendations = [
                        "Enable peer client certificate authentication for etcd",
                        "Set --peer-client-cert-auth=true in etcd configuration",
                        "Ensure all peer nodes have valid certificates",
                        "Follow etcd security best practices"
                    ]
                
                findings.append(result)

        except Exception as e:
            findings.append(CheckResult(
                check_id="etcd_peer_client_cert_auth",
                check_name="Ensure that the --peer-client-cert-auth argument is set to true for etcd",
                status=CheckStatus.ERROR,
                status_extended=f"Error checking etcd_peer_client_cert_auth: {str(e)}",
                resource_id="unknown",
                resource_name="unknown",
                resource_type="Pod",
                severity=CheckSeverity.HIGH
            ))

        return findings

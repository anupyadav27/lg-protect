"""
Ensure that the --client-cert-auth argument is set to true for etcd

This check ensures that client authentication is enabled for the etcd service, which is a key-value store used by Kubernetes for persistent storage of all REST API objects. Enabling client authentication helps in securing access to etcd.
"""

from typing import List
from kubernetes import client
from kubernetes_checks.base import KubernetesCheckBase
from utility.base_reporting import CheckResult, CheckStatus, CheckSeverity

class etcd_client_cert_auth(KubernetesCheckBase):
    """Ensure that the --client-cert-auth argument is set to true for etcd"""

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
                    
                    # Check for --client-cert-auth=true in args
                    if "--client-cert-auth=true" in args:
                        check_passed = True
                        break
                    
                    # Check for --client-cert-auth in args (without value, defaults to true)
                    if "--client-cert-auth" in args:
                        check_passed = True
                        break
                    
                    # Check in command as well
                    if "--client-cert-auth=true" in command or "--client-cert-auth" in command:
                        check_passed = True
                        break
                
                result = CheckResult(
                    check_id="etcd_client_cert_auth",
                    check_name="Ensure that the --client-cert-auth argument is set to true for etcd",
                    status=CheckStatus.PASS if check_passed else CheckStatus.FAIL,
                    status_extended=(
                        f"Etcd has client certificate authentication enabled in pod {pod.metadata.name}."
                        if check_passed else
                        f"Etcd does not have client certificate authentication enabled in pod {pod.metadata.name}."
                    ),
                    resource_id=pod.metadata.name,
                    resource_name=pod.metadata.name,
                    resource_type="Pod",
                    namespace="kube-system",
                    severity=CheckSeverity.HIGH
                )
                
                if not check_passed:
                    result.recommendations = [
                        "Enable client certificate authentication for etcd",
                        "Set --client-cert-auth=true in etcd configuration",
                        "Ensure all clients have valid certificates",
                        "Follow etcd security best practices"
                    ]
                
                findings.append(result)

        except Exception as e:
            findings.append(CheckResult(
                check_id="etcd_client_cert_auth",
                check_name="Ensure that the --client-cert-auth argument is set to true for etcd",
                status=CheckStatus.ERROR,
                status_extended=f"Error checking etcd_client_cert_auth: {str(e)}",
                resource_id="unknown",
                resource_name="unknown",
                resource_type="Pod",
                severity=CheckSeverity.HIGH
            ))

        return findings

"""
Ensure that etcd uses a unique CA file

This check ensures that etcd uses a different CA file from the Kubernetes cluster CA, which helps maintain security boundaries and reduces the risk of compromise.
"""

from typing import List
from kubernetes import client
from kubernetes_checks.base import KubernetesCheckBase
from utility.base_reporting import CheckResult, CheckStatus, CheckSeverity

class etcd_unique_ca(KubernetesCheckBase):
    """Ensure that etcd uses a unique CA file"""

    def execute(self) -> List[CheckResult]:
        findings = []
        try:
            # Get API server pods to check their CA files
            v1_api = client.CoreV1Api(self.provider)
            apiserver_pods = v1_api.list_namespaced_pod(
                namespace="kube-system",
                label_selector="component=kube-apiserver"
            )
            
            # Get etcd pods
            etcd_pods = v1_api.list_namespaced_pod(
                namespace="kube-system",
                label_selector="component=etcd"
            )
            
            # Collect API server CA files
            apiserver_ca_files = []
            for pod in apiserver_pods.items:
                for container in pod.spec.containers or []:
                    args = container.args or []
                    command = container.command or []
                    
                    # Check in args
                    for arg in args:
                        if arg.startswith("--client-ca-file="):
                            apiserver_ca_files.append(arg.split("=")[1])
                    
                    # Check in command
                    for cmd in command:
                        if cmd.startswith("--client-ca-file="):
                            apiserver_ca_files.append(cmd.split("=")[1])
            
            # Check etcd pods
            for pod in etcd_pods.items:
                etcd_ca_files = []
                check_passed = True
                
                # Collect etcd CA files
                for container in pod.spec.containers or []:
                    args = container.args or []
                    command = container.command or []
                    
                    # Check in args
                    for arg in args:
                        if arg.startswith("--trusted-ca-file="):
                            etcd_ca_files.append(arg.split("=")[1])
                    
                    # Check in command
                    for cmd in command:
                        if cmd.startswith("--trusted-ca-file="):
                            etcd_ca_files.append(cmd.split("=")[1])
                
                # Check if etcd uses the same CA as API server
                if any(ca in etcd_ca_files for ca in apiserver_ca_files):
                    check_passed = False
                
                result = CheckResult(
                    check_id="etcd_unique_ca",
                    check_name="Ensure that etcd uses a unique CA file",
                    status=CheckStatus.PASS if check_passed else CheckStatus.FAIL,
                    status_extended=(
                        f"Etcd uses a different CA file from the Kubernetes cluster CA in pod {pod.metadata.name}."
                        if check_passed else
                        f"Etcd does not use a unique CA file, which could compromise its security in pod {pod.metadata.name}."
                    ),
                    resource_id=pod.metadata.name,
                    resource_name=pod.metadata.name,
                    resource_type="Pod",
                    namespace="kube-system",
                    severity=CheckSeverity.HIGH
                )
                
                if not check_passed:
                    result.recommendations = [
                        "Use a unique CA file for etcd",
                        "Configure etcd with a separate CA from the cluster CA",
                        "Maintain security boundaries between etcd and cluster components",
                        "Follow etcd security best practices"
                    ]
                
                findings.append(result)

        except Exception as e:
            findings.append(CheckResult(
                check_id="etcd_unique_ca",
                check_name="Ensure that etcd uses a unique CA file",
                status=CheckStatus.ERROR,
                status_extended=f"Error checking etcd_unique_ca: {str(e)}",
                resource_id="unknown",
                resource_name="unknown",
                resource_type="Pod",
                severity=CheckSeverity.HIGH
            ))

        return findings

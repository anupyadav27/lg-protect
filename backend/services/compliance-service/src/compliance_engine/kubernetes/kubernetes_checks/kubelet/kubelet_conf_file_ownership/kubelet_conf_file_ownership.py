from typing import List
from kubernetes import client
from kubernetes_checks.base import KubernetesCheckBase
from utility.base_reporting import CheckResult, CheckStatus, CheckSeverity

class kubelet_conf_file_ownership(KubernetesCheckBase):
    def execute(self) -> List[CheckResult]:
        findings = []
        try:
            v1_api = client.CoreV1Api(self.provider)
            nodes = v1_api.list_node()
            
            for node in nodes.items:
                result = CheckResult(
                    check_id="kubelet_conf_file_ownership",
                    check_name="Kubelet Configuration File Ownership",
                    status=CheckStatus.PASS,
                    status_extended=f"kubelet.conf file ownership is set to root:root in Node {node.metadata.name}.",
                    resource_id=node.metadata.name,
                    resource_name=node.metadata.name,
                    resource_type="Node",
                    namespace="",
                    severity=CheckSeverity.HIGH
                )
                
                # This check requires access to the node's file system
                # Since we can't directly access the node's file system from the API,
                # we'll mark it as manual verification required
                result.status = CheckStatus.MANUAL
                result.status_extended = f"Prowler is not being executed inside Node {node.metadata.name}, please verify kubelet.conf file ownership manually. The file should be owned by root:root."
                
                findings.append(result)
                
        except Exception as e:
            result = CheckResult(
                check_id="kubelet_conf_file_ownership",
                check_name="Kubelet Configuration File Ownership",
                status=CheckStatus.ERROR,
                status_extended=f"Error checking kubelet configuration file ownership: {str(e)}",
                resource_id="",
                resource_name="",
                resource_type="Node",
                namespace="",
                severity=CheckSeverity.HIGH
            )
            findings.append(result)
        
        return findings

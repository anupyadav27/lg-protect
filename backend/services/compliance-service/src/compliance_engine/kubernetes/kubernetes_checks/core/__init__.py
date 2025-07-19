"""
Kubernetes Core Checks Module

This module contains core security checks for Kubernetes resources like Pods, Services, etc.
"""

from typing import List
from kubernetes_checks.base import KubernetesServiceBase, CheckResult, KubernetesCheckBase
from .service import CorePrivilegedContainers, CoreRootContainers, KubernetesChecksCore


class CorePrivilegedContainers(KubernetesCheckBase):
    """Check for privileged containers in pods."""
    
    def execute(self) -> List[CheckResult]:
        results = []
        try:
            # Get all pods across namespaces
            all_pods = self._get_all_pods()
            
            for pod in all_pods:
                result = CheckResult(
                    check_id="core_privileged_containers",
                    check_name="Core Privileged Containers",
                    status="PASS",
                    status_extended=f"No privileged containers found in pod {pod.name}.",
                    resource_id=pod.name,
                    resource_name=pod.name,
                    resource_type="Pod"
                )
                
                privileged_found = False
                for container in pod.containers.values():
                    if hasattr(container, 'security_context') and container.security_context:
                        if getattr(container.security_context, 'privileged', False):
                            privileged_found = True
                            break
                
                if privileged_found:
                    result.status = "FAIL"
                    result.status_extended = f"Privileged container found in pod {pod.name}."
                    result.recommendations = [
                        "Avoid running containers in privileged mode",
                        "Use security contexts with minimal required privileges",
                        "Consider using Pod Security Standards"
                    ]
                    result.severity = "HIGH"
                
                results.append(result)
                
        except Exception as e:
            self.log_error("Error checking privileged containers", e)
            results.append(CheckResult(
                check_id="core_privileged_containers",
                check_name="Core Privileged Containers",
                status="ERROR",
                status_extended=f"Error checking privileged containers: {str(e)}",
                resource_id="unknown",
                resource_name="unknown",
                resource_type="Pod"
            ))
        
        return results
    
    def _get_all_pods(self):
        """Get all pods across all namespaces."""
        # This would be implemented to get pods from the provider
        return []


class CoreRootContainers(KubernetesCheckBase):
    """Check for containers running as root."""
    
    def execute(self) -> List[CheckResult]:
        results = []
        try:
            all_pods = self._get_all_pods()
            
            for pod in all_pods:
                result = CheckResult(
                    check_id="core_root_containers",
                    check_name="Core Root Containers",
                    status="PASS",
                    status_extended=f"No containers running as root found in pod {pod.name}.",
                    resource_id=pod.name,
                    resource_name=pod.name,
                    resource_type="Pod"
                )
                
                root_container_found = False
                for container in pod.containers.values():
                    if hasattr(container, 'security_context') and container.security_context:
                        run_as_user = getattr(container.security_context, 'run_as_user', None)
                        if run_as_user == 0:
                            root_container_found = True
                            break
                
                if root_container_found:
                    result.status = "FAIL"
                    result.status_extended = f"Container running as root found in pod {pod.name}."
                    result.recommendations = [
                        "Avoid running containers as root user",
                        "Set runAsUser to a non-zero value",
                        "Use security contexts with non-root users"
                    ]
                    result.severity = "MEDIUM"
                
                results.append(result)
                
        except Exception as e:
            self.log_error("Error checking root containers", e)
            results.append(CheckResult(
                check_id="core_root_containers",
                check_name="Core Root Containers",
                status="ERROR",
                status_extended=f"Error checking root containers: {str(e)}",
                resource_id="unknown",
                resource_name="unknown",
                resource_type="Pod"
            ))
        
        return results
    
    def _get_all_pods(self):
        """Get all pods across all namespaces."""
        return []


class KubernetesChecksCore(KubernetesServiceBase):
    """Main class for Core Kubernetes security checks."""
    
    def __init__(self, provider):
        super().__init__(provider)
        self.privileged_containers = CorePrivilegedContainers(provider)
        self.root_containers = CoreRootContainers(provider)
    
    def execute_all_checks(self) -> List[CheckResult]:
        """Execute all Core checks."""
        results = []
        results.extend(self.privileged_containers.execute())
        results.extend(self.root_containers.execute())
        return results 
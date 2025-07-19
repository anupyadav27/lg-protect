"""
Kubernetes APIServer Checks Service Logic

This module contains security checks for the Kubernetes API Server component.
"""

from typing import List, Dict
from kubernetes_checks.base import KubernetesServiceBase, CheckResult, KubernetesCheckBase, DynamicCheckLoader
from utility.base_reporting import CheckStatus


class KubernetesChecksAPIServer(KubernetesServiceBase, DynamicCheckLoader):
    """Main class for API Server security checks."""
    
    def __init__(self, provider):
        super().__init__(provider)
        self.checks: Dict[str, KubernetesCheckBase] = {}
        self._load_checks_dynamically()
    
    def _load_checks_dynamically(self):
        """Dynamically load all check classes from subdirectories."""
        self.checks = self.load_checks_dynamically("apiserver")
    
    def execute_all_checks(self) -> List[CheckResult]:
        """Execute all API Server checks."""
        results = []
        
        for check_name, check_instance in self.checks.items():
            try:
                check_results = check_instance.execute()
                results.extend(check_results)
            except Exception as e:
                print(f"Error executing check {check_name}: {e}")
                # Add error result
                results.append(CheckResult(
                    check_id=check_name,
                    check_name=check_name,
                    status=CheckStatus.ERROR,
                    status_extended=f"Error executing check: {str(e)}",
                    resource_id="unknown",
                    resource_name="unknown",
                    resource_type="Check"
                ))
        
        return results
    
    def get_available_checks(self) -> List[str]:
        """Get list of available check names."""
        return list(self.checks.keys())

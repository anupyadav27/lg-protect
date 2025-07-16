# engine.py
"""
Compliance Engine Orchestrator

This module discovers, executes, and aggregates compliance checks.
"""

import importlib
import pkgutil
from typing import List, Dict, Any, Optional

from checks import accessanalyzer  # Example: import checks package

class ComplianceEngine:
    """
    Orchestrates discovery, execution, and aggregation of compliance checks.
    """

    def __init__(self):
        self.checks = self.discover_checks()

    def discover_checks(self) -> List[Any]:
        """
        Discover all compliance check classes in the checks directory.
        Returns a list of check class objects.
        """
        checks = []
        # For demonstration, only accessanalyzer checks are loaded.
        # In a real implementation, this would recursively walk the checks/ directory.
        for _, module_name, _ in pkgutil.iter_modules(accessanalyzer.__path__):
            module = importlib.import_module(f"checks.accessanalyzer.{module_name}")
            for attr in dir(module):
                obj = getattr(module, attr)
                if isinstance(obj, type) and hasattr(obj, "run"):
                    checks.append(obj)
        return checks

    def run_all(self, service_instances: Dict[str, Any], region_name: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Run all discovered compliance checks.

        Args:
            service_instances: Dict mapping service names to service objects (e.g., {"accessanalyzer": AccessAnalyzerService(...)})
            region_name: Optional AWS region

        Returns:
            List of compliance check result dicts.
        """
        results = []
        for check_cls in self.checks:
            # Determine which service to use based on check class name or metadata
            if hasattr(check_cls, "compliance_name") and "accessanalyzer" in check_cls.__name__.lower():
                service = service_instances.get("accessanalyzer")
            else:
                continue  # Skip if service not found

            check = check_cls()
            try:
                result = check.run(service, region_name=region_name)
                results.append(result.to_dict())
            except Exception as e:
                results.append({
                    "check": check_cls.__name__,
                    "status": "error",
                    "details": str(e)
                })
        return results

# Example usage (not run on import)
if __name__ == "__main__":
    import boto3
    from services.accessanalyzer_service import AccessAnalyzerService

    session = boto3.Session()
    accessanalyzer_service = AccessAnalyzerService(session)
    engine = ComplianceEngine()
    service_instances = {"accessanalyzer": accessanalyzer_service}
    results = engine.run_all(service_instances, region_name="us-east-1")
    for res in results:
        print(res)
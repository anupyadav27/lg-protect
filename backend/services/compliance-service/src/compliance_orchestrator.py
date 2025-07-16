#!/usr/bin/env python3
"""
Compliance-to-Inventory Service Orchestrator

This module orchestrates compliance scans by:
1. Loading compliance requirements from the enhanced CSV
2. Mapping required inventory services for each compliance check
3. Executing inventory scans in the correct dependency order
4. Aggregating results for compliance reporting
"""

import json
import csv
import asyncio
import logging
from pathlib import Path
from typing import Dict, List, Set, Tuple
from dataclasses import dataclass
from datetime import datetime
import requests

@dataclass
class ComplianceCheck:
    framework: str
    control_id: str
    control_name: str
    checks: List[str]
    required_services: List[str]
    inventory_dependencies: List[str]
    resource_types: List[str]
    priority: str
    automation_status: str

@dataclass
class ScanResult:
    service_name: str
    compliance_checks: List[str]
    resources_scanned: int
    compliance_score: float
    violations: List[Dict]
    scan_duration: float
    timestamp: datetime

class ComplianceOrchestrator:
    def __init__(self, config_dir: Path):
        self.config_dir = Path(config_dir)
        self.compliance_mapping = {}
        self.service_dependencies = {}
        self.scan_results = {}
        self.logger = self._setup_logging()
        
    def _setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        return logging.getLogger(__name__)

    async def load_compliance_configuration(self):
        """Load compliance checks and service mappings from configuration files"""
        # Load enhanced CSV mapping
        csv_file = self.config_dir / "enhanced_compliance_checks_mapping.csv"
        service_mapping_file = self.config_dir / "service_compliance_mapping.json"
        
        # Parse CSV file
        with open(csv_file, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                compliance_check = ComplianceCheck(
                    framework=row['Compliance_Framework'],
                    control_id=row['Control_ID'],
                    control_name=row['Control_Name'],
                    checks=json.loads(row['Compliance_Checks']),
                    required_services=json.loads(row['Required_AWS_Services']),
                    inventory_dependencies=json.loads(row['Inventory_Service_Dependencies']),
                    resource_types=json.loads(row['Resource_Types']),
                    priority=row['Priority'],
                    automation_status=row['Automation_Status']
                )
                self.compliance_mapping[row['Control_ID']] = compliance_check
        
        # Load service dependency mapping
        with open(service_mapping_file, 'r') as f:
            self.service_dependencies = json.load(f)
            
        self.logger.info(f"Loaded {len(self.compliance_mapping)} compliance checks")
        self.logger.info(f"Loaded {len(self.service_dependencies['service_compliance_mapping'])} service mappings")

    def get_required_services_for_compliance(self, compliance_frameworks: List[str] = None) -> Dict[str, List[str]]:
        """Get all inventory services required for specified compliance frameworks"""
        required_services = {}
        
        for control_id, check in self.compliance_mapping.items():
            if compliance_frameworks and check.framework not in compliance_frameworks:
                continue
                
            for service in check.inventory_dependencies:
                if service not in required_services:
                    required_services[service] = []
                required_services[service].extend(check.checks)
        
        return required_services

    def resolve_scan_dependencies(self, target_checks: List[str]) -> List[Tuple[str, List[str]]]:
        """Resolve the execution order for compliance checks based on dependencies"""
        execution_plan = []
        dependencies = self.service_dependencies.get('compliance_scan_dependencies', {})
        
        # Group checks by execution order
        execution_groups = {}
        for check in target_checks:
            dep_info = dependencies.get(f"check_{check}", {})
            order = dep_info.get('execution_order', 1)
            
            if order not in execution_groups:
                execution_groups[order] = []
            execution_groups[order].append((check, dep_info.get('required_services', [])))
        
        # Sort by execution order
        for order in sorted(execution_groups.keys()):
            execution_plan.extend(execution_groups[order])
            
        return execution_plan

    async def scan_inventory_service(self, service_name: str, applicable_checks: List[str]) -> ScanResult:
        """Execute inventory scan for a specific service"""
        start_time = datetime.now()
        
        try:
            # Map service name to actual inventory service endpoint
            service_endpoint = self._get_service_endpoint(service_name)
            
            # Call inventory service API
            scan_request = {
                "service": service_name,
                "compliance_checks": applicable_checks,
                "scan_type": "compliance_focused",
                "timestamp": start_time.isoformat()
            }
            
            self.logger.info(f"Scanning {service_name} for {len(applicable_checks)} compliance checks")
            
            # Simulate API call to inventory service
            # In real implementation, this would call your actual inventory service
            result = await self._call_inventory_service(service_endpoint, scan_request)
            
            scan_duration = (datetime.now() - start_time).total_seconds()
            
            return ScanResult(
                service_name=service_name,
                compliance_checks=applicable_checks,
                resources_scanned=result.get('resources_scanned', 0),
                compliance_score=result.get('compliance_score', 0.0),
                violations=result.get('violations', []),
                scan_duration=scan_duration,
                timestamp=start_time
            )
            
        except Exception as e:
            self.logger.error(f"Failed to scan {service_name}: {str(e)}")
            return ScanResult(
                service_name=service_name,
                compliance_checks=applicable_checks,
                resources_scanned=0,
                compliance_score=0.0,
                violations=[{"error": str(e)}],
                scan_duration=0.0,
                timestamp=start_time
            )

    def _get_service_endpoint(self, service_name: str) -> str:
        """Map service name to actual endpoint"""
        service_endpoints = {
            "inventory-service.iam-analyzer": "http://localhost:3001/api/inventory/iam",
            "inventory-service.s3-analyzer": "http://localhost:3001/api/inventory/s3",
            "inventory-service.ec2-analyzer": "http://localhost:3001/api/inventory/ec2",
            "inventory-service.rds-analyzer": "http://localhost:3001/api/inventory/rds",
            "inventory-service.security-analyzer": "http://localhost:3001/api/inventory/security"
        }
        return service_endpoints.get(service_name, "http://localhost:3001/api/inventory/generic")

    async def _call_inventory_service(self, endpoint: str, scan_request: Dict) -> Dict:
        """Call the actual inventory service API"""
        # This is a placeholder - implement actual HTTP calls to your inventory services
        # For now, simulate a response
        await asyncio.sleep(1)  # Simulate scan time
        
        return {
            "resources_scanned": 15,
            "compliance_score": 85.5,
            "violations": [
                {
                    "check": "iam_user_mfa_enabled_console_access",
                    "resource": "user-john-doe",
                    "severity": "HIGH",
                    "message": "MFA not enabled for console access"
                }
            ],
            "scan_metadata": {
                "scan_duration": "1.2s",
                "api_calls": 8,
                "cached_results": 3
            }
        }

    async def execute_compliance_scan(self, 
                                    compliance_frameworks: List[str] = None,
                                    specific_checks: List[str] = None) -> Dict:
        """Execute a comprehensive compliance scan"""
        
        self.logger.info("Starting compliance scan orchestration")
        
        # Determine which services need to be scanned
        if specific_checks:
            target_checks = specific_checks
        else:
            # Get all checks for specified frameworks
            target_checks = []
            for control_id, check in self.compliance_mapping.items():
                if not compliance_frameworks or check.framework in compliance_frameworks:
                    target_checks.extend(check.checks)
        
        # Resolve dependencies and execution order
        execution_plan = self.resolve_scan_dependencies(target_checks)
        
        # Group by services
        service_scan_plan = {}
        for check, required_services in execution_plan:
            for service in required_services:
                if service not in service_scan_plan:
                    service_scan_plan[service] = []
                service_scan_plan[service].append(check)
        
        # Execute scans
        scan_tasks = []
        for service, checks in service_scan_plan.items():
            task = self.scan_inventory_service(service, checks)
            scan_tasks.append(task)
        
        # Wait for all scans to complete
        scan_results = await asyncio.gather(*scan_tasks, return_exceptions=True)
        
        # Aggregate results
        aggregated_results = self._aggregate_scan_results(scan_results)
        
        self.logger.info(f"Compliance scan completed. Overall score: {aggregated_results['overall_score']:.1f}%")
        
        return aggregated_results

    def _aggregate_scan_results(self, scan_results: List[ScanResult]) -> Dict:
        """Aggregate individual service scan results into overall compliance status"""
        
        total_resources = 0
        total_violations = []
        service_scores = []
        scan_summary = []
        
        for result in scan_results:
            if isinstance(result, Exception):
                continue
                
            total_resources += result.resources_scanned
            total_violations.extend(result.violations)
            service_scores.append(result.compliance_score)
            
            scan_summary.append({
                "service": result.service_name,
                "checks_performed": len(result.compliance_checks),
                "resources_scanned": result.resources_scanned,
                "compliance_score": result.compliance_score,
                "violations_found": len(result.violations),
                "scan_duration": result.scan_duration
            })
        
        overall_score = sum(service_scores) / len(service_scores) if service_scores else 0
        
        return {
            "scan_timestamp": datetime.now().isoformat(),
            "overall_score": overall_score,
            "total_resources_scanned": total_resources,
            "total_violations": len(total_violations),
            "service_results": scan_summary,
            "violations_by_severity": self._categorize_violations(total_violations),
            "recommendations": self._generate_recommendations(total_violations)
        }

    def _categorize_violations(self, violations: List[Dict]) -> Dict:
        """Categorize violations by severity"""
        categories = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        
        for violation in violations:
            severity = violation.get("severity", "LOW")
            categories[severity] = categories.get(severity, 0) + 1
            
        return categories

    def _generate_recommendations(self, violations: List[Dict]) -> List[Dict]:
        """Generate prioritized recommendations based on violations"""
        recommendations = []
        
        # Group violations by type for better recommendations
        violation_types = {}
        for violation in violations:
            check = violation.get("check", "unknown")
            if check not in violation_types:
                violation_types[check] = []
            violation_types[check].append(violation)
        
        # Generate recommendations for each violation type
        for check, check_violations in violation_types.items():
            recommendations.append({
                "check": check,
                "affected_resources": len(check_violations),
                "priority": "HIGH" if any(v.get("severity") == "CRITICAL" for v in check_violations) else "MEDIUM",
                "recommendation": f"Address {len(check_violations)} violations for {check}",
                "resources": [v.get("resource") for v in check_violations]
            })
        
        # Sort by priority and number of affected resources
        recommendations.sort(key=lambda x: (x["priority"] == "HIGH", x["affected_resources"]), reverse=True)
        
        return recommendations[:10]  # Return top 10 recommendations

# Example usage
async def main():
    """Example usage of the compliance orchestrator"""
    
    # Initialize orchestrator
    config_dir = Path("/Users/apple/Desktop/lg-protect/backend/services/compliance-service/config")
    orchestrator = ComplianceOrchestrator(config_dir)
    
    # Load configuration
    await orchestrator.load_compliance_configuration()
    
    # Execute compliance scan for specific frameworks
    results = await orchestrator.execute_compliance_scan(
        compliance_frameworks=["CISA", "SOC2"]
    )
    
    # Print results
    print(f"Compliance Scan Results:")
    print(f"Overall Score: {results['overall_score']:.1f}%")
    print(f"Total Resources: {results['total_resources_scanned']}")
    print(f"Total Violations: {results['total_violations']}")
    print(f"Service Results: {len(results['service_results'])} services scanned")
    
    # Show top recommendations
    print("\nTop Recommendations:")
    for i, rec in enumerate(results['recommendations'][:5], 1):
        print(f"{i}. {rec['recommendation']} (Priority: {rec['priority']})")

if __name__ == "__main__":
    asyncio.run(main())
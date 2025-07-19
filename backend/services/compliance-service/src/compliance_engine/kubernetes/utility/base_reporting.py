"""
Base Reporting Format for Kubernetes Security Checks

Provides standardized reporting capabilities for all security checks.
Supports multiple output formats and comprehensive report generation.
"""

import json
import csv
import os
from datetime import datetime
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict
from enum import Enum


class CheckStatus(Enum):
    """Enumeration for check status values."""
    PASS = "PASS"
    FAIL = "FAIL"
    ERROR = "ERROR"
    MANUAL = "MANUAL"
    SKIP = "SKIP"


class CheckSeverity(Enum):
    """Enumeration for check severity levels."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class CheckResult:
    """Standardized check result data structure."""
    check_id: str
    check_name: str
    status: CheckStatus
    status_extended: str
    resource_id: str
    resource_name: str
    resource_type: str
    namespace: Optional[str] = None
    cluster_name: Optional[str] = None
    findings: List[str] = None
    recommendations: List[str] = None
    severity: CheckSeverity = CheckSeverity.MEDIUM
    timestamp: str = None
    execution_time: float = 0.0
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.findings is None:
            self.findings = []
        if self.recommendations is None:
            self.recommendations = []
        if self.timestamp is None:
            self.timestamp = datetime.now().isoformat()
        if self.metadata is None:
            self.metadata = {}


@dataclass
class ReportSummary:
    """Summary statistics for the report."""
    total_checks: int
    passed: int
    failed: int
    errors: int
    manual: int
    skipped: int
    by_severity: Dict[str, int]
    by_component: Dict[str, Dict[str, int]]
    execution_time: float
    cluster_info: Dict[str, Any]
    generated_at: str


class BaseReporter:
    """Base class for generating standardized security check reports."""
    
    def __init__(self, cluster_info: Dict[str, Any] = None):
        """
        Initialize the reporter.
        
        Args:
            cluster_info: Cluster information from discovery
        """
        self.cluster_info = cluster_info or {}
        self.results: List[CheckResult] = []
        self.start_time = datetime.now()
    
    def add_result(self, result: CheckResult):
        """Add a check result to the report."""
        self.results.append(result)
    
    def add_results(self, results: List[CheckResult]):
        """Add multiple check results to the report."""
        self.results.extend(results)
    
    def generate_summary(self) -> ReportSummary:
        """Generate a summary of all results."""
        end_time = datetime.now()
        execution_time = (end_time - self.start_time).total_seconds()
        
        # Count by status
        passed = len([r for r in self.results if r.status == CheckStatus.PASS])
        failed = len([r for r in self.results if r.status == CheckStatus.FAIL])
        errors = len([r for r in self.results if r.status == CheckStatus.ERROR])
        manual = len([r for r in self.results if r.status == CheckStatus.MANUAL])
        skipped = len([r for r in self.results if r.status == CheckStatus.SKIP])
        
        # Count by severity
        by_severity = {
            "LOW": len([r for r in self.results if r.severity == CheckSeverity.LOW]),
            "MEDIUM": len([r for r in self.results if r.severity == CheckSeverity.MEDIUM]),
            "HIGH": len([r for r in self.results if r.severity == CheckSeverity.HIGH]),
            "CRITICAL": len([r for r in self.results if r.severity == CheckSeverity.CRITICAL])
        }
        
        # Count by component (extract from check_id)
        by_component = {}
        for result in self.results:
            component = result.check_id.split("_")[0] if "_" in result.check_id else "unknown"
            if component not in by_component:
                by_component[component] = {"total": 0, "passed": 0, "failed": 0, "errors": 0}
            
            by_component[component]["total"] += 1
            if result.status == CheckStatus.PASS:
                by_component[component]["passed"] += 1
            elif result.status == CheckStatus.FAIL:
                by_component[component]["failed"] += 1
            elif result.status == CheckStatus.ERROR:
                by_component[component]["errors"] += 1
        
        return ReportSummary(
            total_checks=len(self.results),
            passed=passed,
            failed=failed,
            errors=errors,
            manual=manual,
            skipped=skipped,
            by_severity=by_severity,
            by_component=by_component,
            execution_time=execution_time,
            cluster_info=self.cluster_info,
            generated_at=end_time.isoformat()
        )
    
    def generate_json_report(self, output_file: str = None) -> str:
        """Generate a JSON report."""
        summary = self.generate_summary()
        
        report = {
            "summary": asdict(summary),
            "results": [asdict(result) for result in self.results],
            "cluster_info": self.cluster_info
        }
        
        json_content = json.dumps(report, indent=2, default=str)
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(json_content)
        
        return json_content
    
    def generate_csv_report(self, output_file: str = None) -> str:
        """Generate a CSV report."""
        if not self.results:
            return ""
        
        # Define CSV headers
        headers = [
            'check_id', 'check_name', 'status', 'status_extended', 'resource_id',
            'resource_name', 'resource_type', 'namespace', 'cluster_name',
            'severity', 'timestamp', 'execution_time', 'findings', 'recommendations'
        ]
        
        csv_content = []
        csv_content.append(headers)
        
        for result in self.results:
            row = [
                result.check_id,
                result.check_name,
                result.status.value,
                result.status_extended,
                result.resource_id,
                result.resource_name,
                result.resource_type,
                result.namespace or '',
                result.cluster_name or '',
                result.severity.value,
                result.timestamp,
                result.execution_time,
                '; '.join(result.findings),
                '; '.join(result.recommendations)
            ]
            csv_content.append(row)
        
        csv_string = '\n'.join([','.join([f'"{cell}"' for cell in row]) for row in csv_content])
        
        if output_file:
            with open(output_file, 'w', newline='') as f:
                f.write(csv_string)
        
        return csv_string
    
    def generate_text_report(self, output_file: str = None) -> str:
        """Generate a human-readable text report."""
        summary = self.generate_summary()
        
        lines = []
        lines.append("=" * 80)
        lines.append("KUBERNETES SECURITY CHECK REPORT")
        lines.append("=" * 80)
        lines.append(f"Generated: {summary.generated_at}")
        lines.append(f"Execution Time: {summary.execution_time:.2f} seconds")
        lines.append("")
        
        # Cluster Info
        if self.cluster_info:
            lines.append("CLUSTER INFORMATION:")
            lines.append("-" * 30)
            for key, value in self.cluster_info.items():
                lines.append(f"  {key}: {value}")
            lines.append("")
        
        # Summary
        lines.append("SUMMARY:")
        lines.append("-" * 30)
        lines.append(f"Total Checks: {summary.total_checks}")
        lines.append(f"Passed: {summary.passed}")
        lines.append(f"Failed: {summary.failed}")
        lines.append(f"Errors: {summary.errors}")
        lines.append(f"Manual: {summary.manual}")
        lines.append(f"Skipped: {summary.skipped}")
        lines.append("")
        
        # By Severity
        lines.append("BY SEVERITY:")
        lines.append("-" * 30)
        for severity, count in summary.by_severity.items():
            if count > 0:
                lines.append(f"  {severity}: {count}")
        lines.append("")
        
        # By Component
        lines.append("BY COMPONENT:")
        lines.append("-" * 30)
        for component, stats in summary.by_component.items():
            lines.append(f"  {component}: {stats['passed']} passed, {stats['failed']} failed, {stats['errors']} errors")
        lines.append("")
        
        # Failed Checks
        failed_checks = [r for r in self.results if r.status == CheckStatus.FAIL]
        if failed_checks:
            lines.append("FAILED CHECKS:")
            lines.append("-" * 30)
            for check in failed_checks:
                lines.append(f"  - {check.check_name} ({check.severity.value})")
                lines.append(f"    Resource: {check.resource_name} ({check.resource_type})")
                lines.append(f"    Status: {check.status_extended}")
                if check.recommendations:
                    lines.append("    Recommendations:")
                    for rec in check.recommendations:
                        lines.append(f"      * {rec}")
                lines.append("")
        
        # High/Critical Severity Checks
        high_critical = [r for r in self.results if r.severity in [CheckSeverity.HIGH, CheckSeverity.CRITICAL]]
        if high_critical:
            lines.append("HIGH/CRITICAL SEVERITY CHECKS:")
            lines.append("-" * 40)
            for check in high_critical:
                lines.append(f"  - {check.check_name} ({check.severity.value}): {check.status_extended}")
            lines.append("")
        
        text_content = '\n'.join(lines)
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(text_content)
        
        return text_content
    
    def generate_html_report(self, output_file: str = None) -> str:
        """Generate an HTML report."""
        summary = self.generate_summary()
        
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Kubernetes Security Check Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background-color: #f0f0f0; padding: 20px; border-radius: 5px; }}
        .summary {{ background-color: #e8f4f8; padding: 15px; border-radius: 5px; margin: 20px 0; }}
        .failed {{ background-color: #ffe6e6; padding: 15px; border-radius: 5px; margin: 20px 0; }}
        .high-critical {{ background-color: #fff2cc; padding: 15px; border-radius: 5px; margin: 20px 0; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
        .pass {{ color: green; }}
        .fail {{ color: red; }}
        .error {{ color: orange; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Kubernetes Security Check Report</h1>
        <p>Generated: {summary.generated_at}</p>
        <p>Execution Time: {summary.execution_time:.2f} seconds</p>
    </div>
    
    <div class="summary">
        <h2>Summary</h2>
        <p>Total Checks: {summary.total_checks}</p>
        <p>Passed: <span class="pass">{summary.passed}</span></p>
        <p>Failed: <span class="fail">{summary.failed}</span></p>
        <p>Errors: <span class="error">{summary.errors}</span></p>
    </div>
    
    <div class="failed">
        <h2>Failed Checks</h2>
        <table>
            <tr><th>Check</th><th>Resource</th><th>Status</th><th>Severity</th></tr>
"""
        
        failed_checks = [r for r in self.results if r.status == CheckStatus.FAIL]
        for check in failed_checks:
            html_content += f"""
            <tr>
                <td>{check.check_name}</td>
                <td>{check.resource_name} ({check.resource_type})</td>
                <td>{check.status_extended}</td>
                <td>{check.severity.value}</td>
            </tr>
"""
        
        html_content += """
        </table>
    </div>
</body>
</html>
"""
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(html_content)
        
        return html_content


def create_reporter(cluster_info: Dict[str, Any] = None) -> BaseReporter:
    """Factory function to create a reporter instance."""
    return BaseReporter(cluster_info)


# Example usage
if __name__ == "__main__":
    # Example of how to use the reporter
    reporter = create_reporter({
        "cluster_name": "example-cluster",
        "version": "1.24.0"
    })
    
    # Add some example results
    reporter.add_result(CheckResult(
        check_id="apiserver_tls_config",
        check_name="API Server TLS Configuration",
        status=CheckStatus.PASS,
        status_extended="TLS is properly configured",
        resource_id="kube-apiserver",
        resource_name="kube-apiserver",
        resource_type="Pod",
        severity=CheckSeverity.HIGH
    ))
    
    reporter.add_result(CheckResult(
        check_id="core_privileged_containers",
        check_name="Privileged Containers",
        status=CheckStatus.FAIL,
        status_extended="Found privileged container in namespace default",
        resource_id="nginx-pod",
        resource_name="nginx-pod",
        resource_type="Pod",
        namespace="default",
        severity=CheckSeverity.CRITICAL,
        recommendations=["Remove privileged mode from container", "Use security contexts"]
    ))
    
    # Generate reports
    print("Text Report:")
    print(reporter.generate_text_report())
    
    print("\nJSON Report:")
    print(reporter.generate_json_report())

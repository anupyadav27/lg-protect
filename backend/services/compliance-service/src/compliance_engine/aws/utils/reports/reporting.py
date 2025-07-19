"""
Comprehensive Reporting Model

Provides a complete orchestrating reporting system that:
✅ Defines how all checks work
✅ Provides standardized report formats
✅ Ensures consistency across all checks
✅ Automates common tasks like metadata loading
✅ Validates check structure and format
"""

import json
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, Any, Optional, List, Union
from pathlib import Path

logger = logging.getLogger(__name__)


class CheckStatus(Enum):
    """Standardized check statuses"""
    PASS = "PASS"
    FAIL = "FAIL"
    ERROR = "ERROR"
    WARNING = "WARNING"
    SKIP = "SKIP"
    MANUAL = "MANUAL"


class Severity(Enum):
    """Standardized severity levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ComplianceStandard(Enum):
    """Supported compliance standards"""
    AWS_FOUNDATIONAL_SECURITY_BEST_PRACTICES = "AWS_Foundational_Security_Best_Practices"
    CIS_AWS_FOUNDATIONS_BENCHMARK = "CIS_AWS_Foundations_Benchmark"
    NIST_CSF = "NIST_CSF"
    ISO_27001 = "ISO_27001"
    SOC_2 = "SOC_2"
    CUSTOM = "CUSTOM"


@dataclass
class CheckMetadata:
    """Comprehensive check metadata model"""
    
    check_id: str
    check_name: str
    description: str
    severity: Severity
    compliance_standard: ComplianceStandard
    category: str = ""
    tags: List[str] = field(default_factory=list)
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    version: str = "1.0"
    created_date: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "check_id": self.check_id,
            "check_name": self.check_name,
            "description": self.description,
            "severity": self.severity.value,
            "compliance_standard": self.compliance_standard.value,
            "category": self.category,
            "tags": self.tags,
            "remediation": self.remediation,
            "references": self.references,
            "version": self.version,
            "created_date": self.created_date
        }
    
    def validate(self) -> bool:
        """Validate metadata completeness"""
        required_fields = ['check_id', 'check_name', 'description', 'severity', 'compliance_standard']
        for field_name in required_fields:
            if not getattr(self, field_name):
                logger.error(f"Missing required metadata field: {field_name}")
                return False
        return True


@dataclass
class CheckReport:
    """Comprehensive check report model"""
    
    status: CheckStatus
    status_extended: str
    resource: Any
    metadata: CheckMetadata
    region: Optional[str] = None
    account_id: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    execution_time_ms: Optional[int] = None
    error_details: Optional[str] = None
    evidence: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "check_id": self.metadata.check_id,
            "check_name": self.metadata.check_name,
            "status": self.status.value,
            "status_extended": self.status_extended,
            "severity": self.metadata.severity.value,
            "compliance_standard": self.metadata.compliance_standard.value,
            "resource": self._serialize_resource(),
            "region": self.region,
            "account_id": self.account_id,
            "timestamp": self.timestamp,
            "execution_time_ms": self.execution_time_ms,
            "error_details": self.error_details,
            "evidence": self.evidence,
            "metadata": self.metadata.to_dict()
        }
    
    def _serialize_resource(self) -> Dict[str, Any]:
        """Safely serialize resource object"""
        if hasattr(self.resource, 'to_dict'):
            return self.resource.to_dict()
        elif hasattr(self.resource, '__dict__'):
            return self.resource.__dict__
        else:
            return {"resource": str(self.resource)}
    
    def validate(self) -> bool:
        """Validate report completeness"""
        if not self.metadata.validate():
            return False
        if not self.status_extended:
            logger.error("Missing status_extended")
            return False
        return True


@dataclass
class ComplianceReport:
    """Aggregated compliance report"""
    
    scan_id: str
    scan_timestamp: str
    account_id: Optional[str] = None
    regions: List[str] = field(default_factory=list)
    checks_run: int = 0
    checks_passed: int = 0
    checks_failed: int = 0
    checks_error: int = 0
    checks_warning: int = 0
    checks_skipped: int = 0
    execution_time_ms: int = 0
    findings: List[CheckReport] = field(default_factory=list)
    
    def add_finding(self, finding: CheckReport):
        """Add a finding to the report"""
        self.findings.append(finding)
        self.checks_run += 1
        
        if finding.status.value == CheckStatus.PASS.value:
            self.checks_passed += 1
        elif finding.status.value == CheckStatus.FAIL.value:
            self.checks_failed += 1
        elif finding.status.value == CheckStatus.ERROR.value:
            self.checks_error += 1
        elif finding.status.value == CheckStatus.WARNING.value:
            self.checks_warning += 1
        elif finding.status.value == CheckStatus.SKIP.value:
            self.checks_skipped += 1
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "scan_timestamp": self.scan_timestamp,
            "account_id": self.account_id,
            "regions": self.regions,
            "summary": {
                "checks_run": self.checks_run,
                "checks_passed": self.checks_passed,
                "checks_failed": self.checks_failed,
                "checks_error": self.checks_error,
                "checks_warning": self.checks_warning,
                "checks_skipped": self.checks_skipped,
                "execution_time_ms": self.execution_time_ms
            },
            "findings": [finding.to_dict() for finding in self.findings]
        }
    
    def save_to_file(self, filepath: str):
        """Save report to JSON file"""
        with open(filepath, 'w') as f:
            json.dump(self.to_dict(), f, indent=2, default=str)
    
    def get_summary(self) -> Dict[str, Any]:
        """Get compliance summary"""
        total = self.checks_run
        if total == 0:
            compliance_score = 0
        else:
            compliance_score = (self.checks_passed / total) * 100
        
        return {
            "compliance_score": round(compliance_score, 2),
            "total_checks": total,
            "passed": self.checks_passed,
            "failed": self.checks_failed,
            "errors": self.checks_error,
            "warnings": self.checks_warning,
            "skipped": self.checks_skipped
        }


class BaseCheck(ABC):
    """Enhanced base class for all compliance checks"""
    
    def __init__(self):
        self.metadata = self._get_metadata()
        if not self.metadata.validate():
            raise ValueError(f"Invalid metadata for check {self.__class__.__name__}")
    
    @abstractmethod
    def _get_metadata(self) -> CheckMetadata:
        """Get check metadata - must be implemented by subclasses"""
        pass
    
    @abstractmethod
    def execute(self) -> List[CheckReport]:
        """Execute the check - must be implemented by subclasses"""
        pass
    
    def run_with_timing(self, **kwargs) -> List[CheckReport]:
        """Run check with execution timing"""
        import time
        start_time = time.time()
        
        try:
            results = self.execute(**kwargs)
            execution_time = int((time.time() - start_time) * 1000)
            
            # Add timing to all results
            for result in results:
                result.execution_time_ms = execution_time
            
            return results
            
        except Exception as e:
            execution_time = int((time.time() - start_time) * 1000)
            logger.error(f"Error executing check {self.__class__.__name__}: {e}")
            
            # Return error result
            error_result = CheckReport(
                status=CheckStatus.ERROR,
                status_extended=f"Error during check execution: {str(e)}",
                resource=None,
                metadata=self.metadata,
                execution_time_ms=execution_time,
                error_details=str(e)
            )
            return [error_result]


class ReportValidator:
    """Validates check reports and metadata"""
    
    @staticmethod
    def validate_check_report(report: CheckReport) -> bool:
        """Validate a single check report"""
        return report.validate()
    
    @staticmethod
    def validate_compliance_report(report: ComplianceReport) -> bool:
        """Validate a compliance report"""
        for finding in report.findings:
            if not finding.validate():
                return False
        return True


class ReportFormatter:
    """Formats reports for different outputs"""
    
    @staticmethod
    def to_json(report: Union[CheckReport, ComplianceReport]) -> str:
        """Convert report to JSON string"""
        return json.dumps(report.to_dict(), indent=2, default=str)
    
    @staticmethod
    def to_csv(compliance_report: ComplianceReport) -> str:
        """Convert compliance report to CSV format"""
        import csv
        import io
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Header
        writer.writerow([
            'Check ID', 'Check Name', 'Status', 'Severity', 
            'Region', 'Account ID', 'Timestamp', 'Description'
        ])
        
        # Data
        for finding in compliance_report.findings:
            writer.writerow([
                finding.metadata.check_id,
                finding.metadata.check_name,
                finding.status.value,
                finding.metadata.severity.value,
                finding.region or '',
                finding.account_id or '',
                finding.timestamp,
                finding.status_extended
            ])
        
        return output.getvalue()
    
    @staticmethod
    def to_console_summary(compliance_report: ComplianceReport) -> str:
        """Generate console-friendly summary"""
        summary = compliance_report.get_summary()
        
        output = []
        output.append("=" * 80)
        output.append("COMPLIANCE SCAN SUMMARY")
        output.append("=" * 80)
        output.append(f"Scan ID: {compliance_report.scan_id}")
        output.append(f"Timestamp: {compliance_report.scan_timestamp}")
        output.append(f"Account: {compliance_report.account_id or 'N/A'}")
        output.append(f"Regions: {', '.join(compliance_report.regions) or 'N/A'}")
        output.append("")
        output.append(f"Compliance Score: {summary['compliance_score']}%")
        output.append(f"Total Checks: {summary['total_checks']}")
        output.append(f"  ✅ PASS: {summary['passed']}")
        output.append(f"  ❌ FAIL: {summary['failed']}")
        output.append(f"  ⚠️  WARNING: {summary['warnings']}")
        output.append(f"  🔴 ERROR: {summary['errors']}")
        output.append(f"  ⏭️  SKIP: {summary['skipped']}")
        output.append("=" * 80)
        
        return "\n".join(output) 
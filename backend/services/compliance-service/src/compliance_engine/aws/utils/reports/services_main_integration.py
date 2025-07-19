"""
Dynamic Integration Module

Provides seamless integration between the main scanning system and the reporting framework.
Automatically converts raw scan results to structured compliance reports without hardcoding.
"""

import json
import logging
import importlib
import inspect
from typing import Dict, List, Any, Optional, Type
from pathlib import Path
from datetime import datetime

from .reporting import (
    ComplianceReport, CheckReport, CheckMetadata, CheckStatus, 
    Severity, ComplianceStandard, BaseCheck
)

logger = logging.getLogger(__name__)

class DynamicReportConverter:
    """
    Dynamically converts raw scan results to structured compliance reports
    by discovering and using the actual compliance check classes.
    """
    
    def __init__(self, services_base_path: str = "services"):
        self.services_base_path = Path(services_base_path)
        self.check_classes_cache = {}
        self._discover_compliance_checks()
    
    def _discover_compliance_checks(self):
        """Discover all compliance check classes from the services folder"""
        logger.info(f"🔍 Discovering compliance checks from: {self.services_base_path}")
        
        if not self.services_base_path.exists():
            logger.warning(f"Services directory not found: {self.services_base_path}")
            return
        
        # Walk through all service directories
        for service_dir in self.services_base_path.iterdir():
            if not service_dir.is_dir() or service_dir.name.startswith('__'):
                continue
                
            logger.info(f"📁 Processing service: {service_dir.name}")
            
            # Look for compliance check directories
            for check_dir in service_dir.iterdir():
                if not check_dir.is_dir() or check_dir.name.startswith('__'):
                    continue
                
                # Look for the main check file
                check_file = check_dir / f"{check_dir.name}.py"
                if check_file.exists():
                    self._load_check_class(service_dir.name, check_dir.name, check_file)
    
    def _load_check_class(self, service_name: str, check_name: str, check_file: Path):
        """Load a compliance check class from a file"""
        try:
            # Create module path
            module_path = f"{self.services_base_path.name}.{service_name}.{check_name}.{check_name}"
            
            # Import the module
            module = importlib.import_module(module_path)
            
            # Find the check class (should inherit from BaseCheck)
            check_class = None
            for name, obj in inspect.getmembers(module):
                if (inspect.isclass(obj) and 
                    issubclass(obj, BaseCheck) and 
                    obj != BaseCheck):
                    check_class = obj
                    break
            
            if check_class:
                cache_key = f"{service_name}.{check_name}"
                self.check_classes_cache[cache_key] = check_class
                logger.info(f"   ✅ Loaded check class: {check_class.__name__}")
            else:
                logger.warning(f"   ❌ No BaseCheck subclass found in {module_path}")
                
        except ImportError as e:
            logger.warning(f"   ❌ Could not import {service_name}.{check_name}: {e}")
        except Exception as e:
            logger.error(f"   ❌ Error loading {service_name}.{check_name}: {e}")
    
    def get_check_class(self, service_name: str, check_name: str) -> Optional[Type[BaseCheck]]:
        """Get a compliance check class by service and check name"""
        cache_key = f"{service_name}.{check_name}"
        return self.check_classes_cache.get(cache_key)
    
    def get_all_check_classes(self) -> Dict[str, Type[BaseCheck]]:
        """Get all discovered check classes"""
        return self.check_classes_cache.copy()
    
    def convert_raw_result_to_check_report(self, 
                                         raw_result: Dict[str, Any],
                                         service_name: str,
                                         region: str,
                                         account_id: str) -> Optional[CheckReport]:
        """
        Convert a raw scan result to a structured CheckReport
        
        Args:
            raw_result: Raw result from the scanning system
            service_name: Name of the service (e.g., 'acm', 'account')
            region: AWS region
            account_id: AWS account ID
            
        Returns:
            CheckReport object or None if conversion fails
        """
        try:
            # Extract check name from raw result
            check_name = self._extract_check_name(raw_result, service_name)
            if not check_name:
                logger.warning(f"Could not extract check name from result: {raw_result}")
                return None
            
            # Get the check class
            check_class = self.get_check_class(service_name, check_name)
            if not check_class:
                logger.warning(f"Check class not found for {service_name}.{check_name}")
                return self._create_fallback_check_report(raw_result, service_name, check_name, region, account_id)
            
            # Create check instance to get metadata
            check_instance = check_class()
            metadata = check_instance.metadata
            
            # Determine status
            status = self._determine_status(raw_result)
            
            # Create CheckReport
            check_report = CheckReport(
                status=status,
                status_extended=self._create_status_extended(raw_result),
                resource=raw_result.get('resource', raw_result),
                metadata=metadata,
                region=region,
                account_id=account_id,
                timestamp=datetime.now().isoformat(),
                evidence=raw_result.get('evidence', {}),
                error_details=raw_result.get('error')
            )
            
            return check_report
            
        except Exception as e:
            logger.error(f"Error converting raw result to CheckReport: {e}")
            return None
    
    def _extract_check_name(self, raw_result: Dict[str, Any], service_name: str) -> Optional[str]:
        """Extract check name from raw result"""
        # Try different possible fields
        possible_fields = ['check_name', 'check_id', 'rule_name', 'rule_id', 'test_name']
        
        for field in possible_fields:
            if field in raw_result:
                return raw_result[field]
        
        # Try to extract from service name and result structure
        if 'issue' in raw_result or 'violation' in raw_result:
            return f"{service_name}_compliance_check"
        
        return None
    
    def _determine_status(self, raw_result: Dict[str, Any]) -> CheckStatus:
        """Determine CheckStatus from raw result"""
        # Check for explicit status
        if 'status' in raw_result:
            status_str = raw_result['status'].upper()
            try:
                return CheckStatus(status_str)
            except ValueError:
                pass
        
        # Check for issues/violations
        if raw_result.get('issue') or raw_result.get('violation') or raw_result.get('failed'):
            return CheckStatus.FAIL
        
        # Check for errors
        if raw_result.get('error') or raw_result.get('exception'):
            return CheckStatus.ERROR
        
        # Check for warnings
        if raw_result.get('warning'):
            return CheckStatus.WARNING
        
        # Default to PASS if no issues found
        return CheckStatus.PASS
    
    def _create_status_extended(self, raw_result: Dict[str, Any]) -> str:
        """Create status_extended description from raw result"""
        if raw_result.get('error'):
            return f"Error: {raw_result['error']}"
        
        if raw_result.get('issue'):
            return f"Issue found: {raw_result['issue']}"
        
        if raw_result.get('violation'):
            return f"Violation: {raw_result['violation']}"
        
        if raw_result.get('warning'):
            return f"Warning: {raw_result['warning']}"
        
        if raw_result.get('message'):
            return raw_result['message']
        
        return "Check completed successfully"
    
    def _create_fallback_check_report(self, 
                                    raw_result: Dict[str, Any],
                                    service_name: str,
                                    check_name: str,
                                    region: str,
                                    account_id: str) -> CheckReport:
        """Create a fallback CheckReport when check class is not found"""
        # Create basic metadata
        metadata = CheckMetadata(
            check_id=f"{service_name}_{check_name}",
            check_name=f"{service_name.title()} {check_name.replace('_', ' ').title()}",
            description=f"Compliance check for {service_name} service",
            severity=Severity.MEDIUM,
            compliance_standard=ComplianceStandard.AWS_FOUNDATIONAL_SECURITY_BEST_PRACTICES,
            category=service_name
        )
        
        # Determine status
        status = self._determine_status(raw_result)
        
        return CheckReport(
            status=status,
            status_extended=self._create_status_extended(raw_result),
            resource=raw_result.get('resource', raw_result),
            metadata=metadata,
            region=region,
            account_id=account_id,
            timestamp=datetime.now().isoformat(),
            evidence=raw_result.get('evidence', {}),
            error_details=raw_result.get('error')
        )

class UnifiedComplianceReporter:
    """
    Main class for integrating the unified scanning system with structured reporting
    """
    
    def __init__(self, services_base_path: str = "services"):
        self.converter = DynamicReportConverter(services_base_path)
        self.logger = logging.getLogger(__name__)
    
    def convert_scan_results_to_compliance_report(self, 
                                                scan_results: Dict[str, Any],
                                                scan_id: Optional[str] = None) -> ComplianceReport:
        """
        Convert unified scan results to structured ComplianceReport
        
        Args:
            scan_results: Results from engine.py run_comprehensive_scan()
            scan_id: Optional scan ID (will use from results if not provided)
            
        Returns:
            Structured ComplianceReport
        """
        # Extract scan metadata
        scan_id = scan_id or scan_results.get('scan_id', f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        scan_timestamp = scan_results.get('start_time', datetime.now().isoformat())
        
        # Create compliance report
        compliance_report = ComplianceReport(
            scan_id=scan_id,
            scan_timestamp=scan_timestamp
        )
        
        # Process all targets
        targets = scan_results.get('targets', [])
        self.logger.info(f"Converting {len(targets)} scan targets to compliance report")
        
        for target_result in targets:
            if not target_result.get('success', False):
                continue
            
            target = target_result['target']
            raw_results = target_result.get('results', [])
            
            # Extract target metadata
            account_id = target.get('account_id')
            region = target.get('region')
            service_name = target.get('service_name')
            
            # Convert each raw result to CheckReport
            for raw_result in raw_results:
                check_report = self.converter.convert_raw_result_to_check_report(
                    raw_result, service_name, region, account_id
                )
                
                if check_report:
                    compliance_report.add_finding(check_report)
                    self.logger.debug(f"Added finding: {check_report.metadata.check_id}")
        
        # Calculate execution time
        if 'start_time' in scan_results and 'end_time' in scan_results:
            start_time = datetime.fromisoformat(scan_results['start_time'])
            end_time = datetime.fromisoformat(scan_results['end_time'])
            compliance_report.execution_time_ms = int((end_time - start_time).total_seconds() * 1000)
        
        self.logger.info(f"✅ Converted scan results to compliance report: {len(compliance_report.findings)} findings")
        return compliance_report
    
    def save_compliance_report(self, 
                             compliance_report: ComplianceReport, 
                             output_dir: str = "output",
                             filename_prefix: str = "compliance_report") -> str:
        """
        Save compliance report to file
        
        Args:
            compliance_report: The compliance report to save
            output_dir: Output directory
            filename_prefix: Prefix for the filename
            
        Returns:
            Path to saved file
        """
        output_path = Path(output_dir)
        output_path.mkdir(exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{filename_prefix}_{timestamp}.json"
        filepath = output_path / filename
        
        compliance_report.save_to_file(str(filepath))
        self.logger.info(f"💾 Saved compliance report to: {filepath}")
        
        return str(filepath)
    
    def display_compliance_summary(self, compliance_report: ComplianceReport):
        """Display a comprehensive compliance summary"""
        from .reporting import ReportFormatter
        
        # Get console summary
        summary_text = ReportFormatter.to_console_summary(compliance_report)
        print(summary_text)
        
        # Additional details
        print(f"\n📋 Detailed Breakdown:")
        
        # Group findings by service
        findings_by_service = {}
        for finding in compliance_report.findings:
            service = finding.metadata.category or "unknown"
            if service not in findings_by_service:
                findings_by_service[service] = {"pass": 0, "fail": 0, "error": 0}
            
            if finding.status == CheckStatus.PASS:
                findings_by_service[service]["pass"] += 1
            elif finding.status == CheckStatus.FAIL:
                findings_by_service[service]["fail"] += 1
            else:
                findings_by_service[service]["error"] += 1
        
        for service, counts in findings_by_service.items():
            total = sum(counts.values())
            if total > 0:
                pass_rate = (counts["pass"] / total) * 100
                print(f"  🔧 {service.upper()}: {counts['pass']}/{total} passed ({pass_rate:.1f}%)")
        
        # Show critical findings
        critical_findings = [f for f in compliance_report.findings 
                           if f.metadata.severity == Severity.CRITICAL and f.status == CheckStatus.FAIL]
        
        if critical_findings:
            print(f"\n🚨 Critical Findings ({len(critical_findings)}):")
            for finding in critical_findings[:5]:  # Show first 5
                print(f"  • {finding.metadata.check_name}: {finding.status_extended}")
            if len(critical_findings) > 5:
                print(f"  ... and {len(critical_findings) - 5} more critical findings")

# Global instance for easy access
unified_compliance_reporter = UnifiedComplianceReporter() 
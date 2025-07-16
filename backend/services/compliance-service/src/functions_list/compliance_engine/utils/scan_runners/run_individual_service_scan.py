#!/usr/bin/env python3
"""
Unified Compliance Scan Runner

Provides a unified interface for running compliance scans across all services
with hierarchical reporting structure.
"""

import os
import json
import uuid
import logging
from datetime import datetime
from typing import List, Optional, Type, Dict, Any
import boto3

from utils.reporting import (
    BaseCheck, ComplianceReport, CheckReport, CheckStatus,
    ReportFormatter
)

logger = logging.getLogger(__name__)


class ComplianceScanRunner:
    """Unified scan runner for all compliance services"""
    
    def __init__(self):
        self.session = None
    
    def run_service_scan(
        self, 
        service_name: str,
        check_classes: List[Type[BaseCheck]],
        regions: Optional[List[str]] = None,
        account_id: Optional[str] = None,
        client_initializer=None
    ) -> ComplianceReport:
        """
        Run compliance scan for a specific service.
        
        Args:
            service_name: Name of the service (e.g., 'acm', 'account')
            check_classes: List of check classes to run
            regions: List of AWS regions to scan
            account_id: AWS account ID
            client_initializer: Function to initialize service client
            
        Returns:
            ComplianceReport with all findings
        """
        start_time = datetime.now()
        
        # Initialize AWS session
        if not self.session:
            self.session = boto3.Session()
        
        # Initialize service client if provided
        if client_initializer:
            client_initializer(self.session, regions)
            logger.info(f"Initialized {service_name} client for regions: {regions}")
        
        # Create report
        report = ComplianceReport(
            scan_id=str(uuid.uuid4()),
            scan_timestamp=datetime.now().isoformat(),
            account_id=account_id,
            regions=regions or ['us-east-1']
        )
        
        # Run each check
        for check_class in check_classes:
            try:
                logger.info(f"Running check: {check_class.__name__}")
                check = check_class()
                findings = check.run_with_timing()
                report.findings.extend(findings)
                logger.info(f"Check {check_class.__name__} completed with {len(findings)} findings")
            except Exception as e:
                logger.error(f"Error running check {check_class.__name__}: {e}")
        
        # Calculate execution time
        end_time = datetime.now()
        execution_time = (end_time - start_time).total_seconds() * 1000
        report.execution_time_ms = int(execution_time)
        
        logger.info(f"{service_name.upper()} scan completed. Found {len(report.findings)} findings in {execution_time:.0f}ms")
        
        return report
    
    def save_reports(self, report: ComplianceReport, output_dir: str = "output"):
        """
        Save reports in hierarchical structure.
        
        Args:
            report: ComplianceReport to save
            output_dir: Base output directory
        """
        # Create timestamped scan directory
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        scan_dir = os.path.join(output_dir, f"scan_{timestamp}")
        os.makedirs(scan_dir, exist_ok=True)
        
        # Create subdirectories
        overall_dir = os.path.join(scan_dir, "overall")
        services_dir = os.path.join(scan_dir, "services")
        os.makedirs(overall_dir, exist_ok=True)
        os.makedirs(services_dir, exist_ok=True)
        
        # Group findings by service
        service_findings = {}
        for finding in report.findings:
            # Extract service name from check name (e.g., "ACM Certificates..." -> "acm")
            check_name = finding.metadata.check_name
            service_name = check_name.split()[0].lower()
            
            if service_name not in service_findings:
                service_findings[service_name] = []
            service_findings[service_name].append(finding)
        
        # Save overall reports
        json_file = os.path.join(overall_dir, "compliance_report.json")
        report.save_to_file(json_file)
        logger.info(f"Overall JSON report saved to: {json_file}")
        
        # Save CSV report
        csv_file = os.path.join(overall_dir, "compliance_report.csv")
        csv_content = ReportFormatter.to_csv(report)
        with open(csv_file, 'w') as f:
            f.write(csv_content)
        logger.info(f"Overall CSV report saved to: {csv_file}")
        
        # Save TXT report
        txt_file = os.path.join(overall_dir, "compliance_summary.txt")
        txt_content = ReportFormatter.to_console_summary(report)
        with open(txt_file, 'w') as f:
            f.write(txt_content)
        logger.info(f"Overall text report saved to: {txt_file}")
        
        # Save service-specific reports with check-level breakdown
        for service_name, findings in service_findings.items():
            service_dir = os.path.join(services_dir, service_name)
            os.makedirs(service_dir, exist_ok=True)
            
            # Create service-specific report
            service_report = ComplianceReport(
                scan_id=report.scan_id,
                scan_timestamp=report.scan_timestamp,
                account_id=report.account_id,
                regions=report.regions
            )
            
            # Add findings for this service
            for finding in findings:
                service_report.add_finding(finding)
            
            # Save service-specific reports
            service_json_file = os.path.join(service_dir, f"{service_name}_report.json")
            service_report.save_to_file(service_json_file)
            
            service_csv_file = os.path.join(service_dir, f"{service_name}_report.csv")
            service_csv_content = ReportFormatter.to_csv(service_report)
            with open(service_csv_file, 'w') as f:
                f.write(service_csv_content)
            
            service_txt_file = os.path.join(service_dir, f"{service_name}_summary.txt")
            service_txt_content = ReportFormatter.to_console_summary(service_report)
            with open(service_txt_file, 'w') as f:
                f.write(service_txt_content)
            
            # Create check-level breakdown
            check_findings = {}
            for finding in findings:
                check_name = finding.metadata.check_name
                if check_name not in check_findings:
                    check_findings[check_name] = []
                check_findings[check_name].append(finding)
            
            # Save individual check reports
            checks_dir = os.path.join(service_dir, "checks")
            os.makedirs(checks_dir, exist_ok=True)
            
            for check_name, check_findings_list in check_findings.items():
                # Create check-specific report
                check_report = ComplianceReport(
                    scan_id=report.scan_id,
                    scan_timestamp=report.scan_timestamp,
                    account_id=report.account_id,
                    regions=report.regions
                )
                
                # Add findings for this check
                for finding in check_findings_list:
                    check_report.add_finding(finding)
                
                # Save check-specific reports
                check_json_file = os.path.join(checks_dir, f"{check_name}_report.json")
                check_report.save_to_file(check_json_file)
                
                check_csv_file = os.path.join(checks_dir, f"{check_name}_report.csv")
                check_csv_content = ReportFormatter.to_csv(check_report)
                with open(check_csv_file, 'w') as f:
                    f.write(check_csv_content)
                
                check_txt_file = os.path.join(checks_dir, f"{check_name}_summary.txt")
                check_txt_content = ReportFormatter.to_console_summary(check_report)
                with open(check_txt_file, 'w') as f:
                    f.write(check_txt_content)
            
            logger.info(f"Service {service_name} reports saved to: {service_dir}")
            logger.info(f"Check-level reports saved to: {checks_dir}")
        
        # Create scan metadata
        metadata = {
            "scan_id": report.scan_id,
            "scan_timestamp": report.scan_timestamp,
            "account_id": report.account_id,
            "regions": report.regions,
            "services_scanned": list(service_findings.keys()),
            "total_findings": len(report.findings),
            "compliance_score": report.get_summary()["compliance_score"],
            "execution_time_ms": report.execution_time_ms,
            "output_structure": {
                "overall": "Overall scan results and summary",
                "services": "Service-specific reports and findings",
                "checks": "Individual check function reports within each service"
            },
            "hierarchy": {
                "level_1": "Overall compliance summary and cross-service findings",
                "level_2": "Service-specific reports (e.g., ACM, Account, S3)",
                "level_3": "Individual check function reports within each service"
            }
        }
        
        metadata_file = os.path.join(scan_dir, "scan_metadata.json")
        with open(metadata_file, 'w') as f:
            json.dump(metadata, f, indent=2, default=str)
        logger.info(f"Scan metadata saved to: {metadata_file}")
        
        # Print summary
        summary = report.get_summary()
        print(f"\n=== Compliance Scan Summary ===")
        print(f"Compliance Score: {summary['compliance_score']}%")
        print(f"Total Checks: {summary['total_checks']}")
        print(f"Passed: {summary['passed']}")
        print(f"Failed: {summary['failed']}")
        print(f"Errors: {summary['errors']}")
        print(f"Warnings: {summary['warnings']}")
        print(f"Skipped: {summary['skipped']}")
        print(f"Execution Time: {report.execution_time_ms}ms")
        print(f"\n📁 Reports saved to: {scan_dir}")
        print(f"📊 Overall reports: {overall_dir}")
        print(f"🔧 Service reports: {services_dir}")
        print(f"🔍 Check-level reports: {services_dir}/*/checks/")
        print(f"📋 Services scanned: {', '.join(service_findings.keys())}")
        print(f"\n📋 Report Hierarchy:")
        print(f"   Level 1: Overall compliance summary")
        print(f"   Level 2: Service-specific reports")
        print(f"   Level 3: Individual check function reports")


# Service-specific convenience functions
def run_acm_scan(regions: Optional[List[str]] = None, account_id: Optional[str] = None) -> ComplianceReport:
    """
    Run ACM compliance scan using the unified runner.
    
    Args:
        regions: List of AWS regions to scan
        account_id: AWS account ID
        
    Returns:
        ComplianceReport with all findings
    """
    from checks.acm.acm_client import initialize_acm_client
    from checks.acm.acm_certificates_with_secure_key_algorithms.acm_certificates_with_secure_key_algorithms import acm_certificates_with_secure_key_algorithms
    from checks.acm.acm_certificates_transparency_logs_enabled.acm_certificates_transparency_logs_enabled import acm_certificates_transparency_logs_enabled
    from checks.acm.acm_certificates_expiration_check.acm_certificates_expiration_check import acm_certificates_expiration_check
    
    runner = ComplianceScanRunner()
    return runner.run_service_scan(
        service_name="acm",
        check_classes=[
            acm_certificates_with_secure_key_algorithms,
            acm_certificates_transparency_logs_enabled,
            acm_certificates_expiration_check
        ],
        regions=regions,
        account_id=account_id,
        client_initializer=initialize_acm_client
    )


def run_account_scan(regions: Optional[List[str]] = None, account_id: Optional[str] = None) -> ComplianceReport:
    """
    Run account compliance scan using the unified runner.
    
    Args:
        regions: List of AWS regions to scan (not used for account-level checks)
        account_id: AWS account ID
        
    Returns:
        ComplianceReport with all findings
    """
    from checks.account.account_client import initialize_account_client
    from checks.account.account_maintain_current_contact_details.account_maintain_current_contact_details import account_maintain_current_contact_details
    from checks.account.account_security_contact_information_is_registered.account_security_contact_information_is_registered import account_security_contact_information_is_registered
    from checks.account.account_security_questions_are_registered_in_the_aws_account.account_security_questions_are_registered_in_the_aws_account import account_security_questions_are_registered_in_the_aws_account
    from checks.account.account_maintain_different_contact_details_to_security_billing_and_operations.account_maintain_different_contact_details_to_security_billing_and_operations import account_maintain_different_contact_details_to_security_billing_and_operations
    
    runner = ComplianceScanRunner()
    return runner.run_service_scan(
        service_name="account",
        check_classes=[
            account_maintain_current_contact_details,
            account_security_contact_information_is_registered,
            account_security_questions_are_registered_in_the_aws_account,
            account_maintain_different_contact_details_to_security_billing_and_operations
        ],
        regions=regions,
        account_id=account_id,
        client_initializer=initialize_account_client
    )


def run_accessanalyzer_scan(regions: Optional[List[str]] = None, account_id: Optional[str] = None) -> ComplianceReport:
    """
    Run AccessAnalyzer compliance scan using the unified runner.
    
    Args:
        regions: List of AWS regions to scan
        account_id: AWS account ID
        
    Returns:
        ComplianceReport with all findings
    """
    from checks.accessanalyzer.accessanalyzer_client import initialize_accessanalyzer_client
    from checks.accessanalyzer.accessanalyzer_enabled.accessanalyzer_enabled import accessanalyzer_enabled
    from checks.accessanalyzer.accessanalyzer_enabled_without_findings.accessanalyzer_enabled_without_findings import accessanalyzer_enabled_without_findings
    
    runner = ComplianceScanRunner()
    return runner.run_service_scan(
        service_name="accessanalyzer",
        check_classes=[
            accessanalyzer_enabled,
            accessanalyzer_enabled_without_findings
        ],
        regions=regions,
        account_id=account_id,
        client_initializer=initialize_accessanalyzer_client
    )


if __name__ == "__main__":
    # Example usage
    print("Running ACM compliance scan...")
    compliance_report = run_acm_scan(regions=['us-east-1'])
    
    # Save reports
    runner = ComplianceScanRunner()
    runner.save_reports(compliance_report) 
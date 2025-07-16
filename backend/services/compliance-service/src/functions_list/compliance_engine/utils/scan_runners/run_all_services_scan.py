#!/usr/bin/env python3
"""
Comprehensive Compliance Scan Runner

Runs all available services and saves reports in unified structure.
"""

from .run_individual_service_scan import (
    run_acm_scan, run_account_scan, run_accessanalyzer_scan, ComplianceScanRunner,
    ComplianceReport
)
from utils.reporting import CheckStatus
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def run_comprehensive_scan(regions=None, account_id=None):
    """
    Run comprehensive scan across all available services.
    
    Args:
        regions: List of AWS regions to scan
        account_id: AWS account ID
        
    Returns:
        Comprehensive ComplianceReport with all findings
    """
    logger.info("Starting comprehensive compliance scan...")
    
    # Run all available service scans
    service_reports = []
    
    # Run ACM scan
    try:
        logger.info("Running ACM scan...")
        acm_report = run_acm_scan(regions, account_id)
        service_reports.append(("acm", acm_report))
        logger.info(f"ACM scan completed with {len(acm_report.findings)} findings")
    except Exception as e:
        logger.error(f"Error running ACM scan: {e}")
    
    # Run Account scan
    try:
        logger.info("Running Account scan...")
        account_report = run_account_scan(regions, account_id)
        service_reports.append(("account", account_report))
        logger.info(f"Account scan completed with {len(account_report.findings)} findings")
    except Exception as e:
        logger.error(f"Error running Account scan: {e}")
    
    # Run AccessAnalyzer scan
    try:
        logger.info("Running AccessAnalyzer scan...")
        accessanalyzer_report = run_accessanalyzer_scan(regions, account_id)
        service_reports.append(("accessanalyzer", accessanalyzer_report))
        logger.info(f"AccessAnalyzer scan completed with {len(accessanalyzer_report.findings)} findings")
    except Exception as e:
        logger.error(f"Error running AccessAnalyzer scan: {e}")
    
    # TODO: Add more services as they are onboarded
    # try:
    #     logger.info("Running S3 scan...")
    #     s3_report = run_s3_scan(regions, account_id)
    #     service_reports.append(("s3", s3_report))
    #     logger.info(f"S3 scan completed with {len(s3_report.findings)} findings")
    # except Exception as e:
    #     logger.error(f"Error running S3 scan: {e}")
    
    # Combine all findings into comprehensive report
    if not service_reports:
        logger.error("No service reports generated")
        return None
    
    # Use the first report as base and add all findings
    base_report = service_reports[0][1]
    comprehensive_report = ComplianceReport(
        scan_id=base_report.scan_id,
        scan_timestamp=base_report.scan_timestamp,
        account_id=base_report.account_id,
        regions=base_report.regions
    )
    
    # Add all findings from all services
    total_findings = 0
    for service_name, report in service_reports:
        for finding in report.findings:
            comprehensive_report.add_finding(finding)
            total_findings += 1
    
    # Calculate total execution time
    total_time = sum(report.execution_time_ms for _, report in service_reports)
    comprehensive_report.execution_time_ms = total_time
    
    logger.info(f"Comprehensive scan completed with {total_findings} total findings")
    
    return comprehensive_report


if __name__ == "__main__":
    # Run comprehensive scan
    comprehensive_report = run_comprehensive_scan(regions=['us-east-1'])
    
    if comprehensive_report:
        # Save reports with unified structure
        runner = ComplianceScanRunner()
        runner.save_reports(comprehensive_report)
    else:
        logger.error("Comprehensive scan failed") 
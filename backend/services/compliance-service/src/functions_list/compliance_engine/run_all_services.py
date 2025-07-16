#!/usr/bin/env python3
"""
All Services Scan Runner - Entry Point

Convenient script to run comprehensive compliance scans across all services.
"""

import sys
import os

# Add the current directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from utils.scan_runners import run_comprehensive_scan

if __name__ == "__main__":
    # Run comprehensive scan
    comprehensive_report = run_comprehensive_scan(regions=['us-east-1'])
    
    if comprehensive_report:
        # Save reports with unified structure
        from utils.scan_runners import ComplianceScanRunner
        runner = ComplianceScanRunner()
        runner.save_reports(comprehensive_report)
    else:
        print("Comprehensive scan failed") 
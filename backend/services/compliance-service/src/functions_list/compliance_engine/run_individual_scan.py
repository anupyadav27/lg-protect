#!/usr/bin/env python3
"""
Individual Service Scan Runner - Entry Point

Convenient script to run individual service compliance scans.
"""

import sys
import os

# Add the current directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from utils.scan_runners import run_acm_scan, ComplianceScanRunner

if __name__ == "__main__":
    print("Running ACM compliance scan...")
    compliance_report = run_acm_scan(regions=['us-east-1'])
    
    # Save reports
    runner = ComplianceScanRunner()
    runner.save_reports(compliance_report) 
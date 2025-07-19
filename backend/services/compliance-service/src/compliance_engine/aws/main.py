#!/usr/bin/env python3
"""
Unified Compliance Scanning Main Entry Point

Demonstrates the unified approach:
- discovery_tools: Defines ScanTargets
- engine.py: Executes ScanTargets
- base.py: Provides foundation classes
- services_main_integration.py: Converts to structured compliance reports
"""

import sys
import os
import logging
from datetime import datetime

# Add current directory to path
sys.path.insert(0, os.getcwd())

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def main():
    """Main entry point for unified compliance scanning with structured reporting"""
    print("🔍 Unified Compliance Scanning System with Dynamic Reporting")
    print("=" * 70)
    print("🏗️ Architecture:")
    print("  • discovery_tools: Target Definition")
    print("  • engine.py: Target Execution")
    print("  • base.py: Foundation Classes")
    print("  • services_main_integration.py: Structured Reporting")
    print("=" * 70)
    
    try:
        # Import the unified engine
        from engine import ComplianceEngineOrchestrator
        
        # Import the services-main integration system
        from utils.reports.services_main_integration import unified_compliance_reporter
        
        # Initialize the orchestrator
        print("\n🚀 Initializing Unified Compliance Engine...")
        orchestrator = ComplianceEngineOrchestrator()
        
        # Display available services
        available_services = orchestrator.checks
        print(f"🔧 Available Services: {len(available_services)}")
        for service in available_services:
            print(f"  • {service}")
        
        # Run comprehensive scan
        print(f"\n🎯 Running Comprehensive Scan...")
        print("   This will:")
        print("   1. Discover all accounts and regions")
        print("   2. Generate ScanTargets for all combinations")
        print("   3. Execute all targets in parallel")
        print("   4. Collect raw results")
        print("   5. Convert to structured compliance reports")
        
        # Start the scan
        start_time = datetime.now()
        raw_results = orchestrator.run_comprehensive_scan(max_workers=5)
        end_time = datetime.now()
        
        # Display raw results summary
        print(f"\n✅ Raw scan completed in {(end_time - start_time).total_seconds():.1f} seconds")
        orchestrator.display_results_summary(raw_results)
        
        # Convert to structured compliance report
        print(f"\n🔄 Converting to Structured Compliance Report...")
        compliance_report = unified_compliance_reporter.convert_scan_results_to_compliance_report(raw_results)
        
        # Display structured compliance summary
        print(f"\n📊 Structured Compliance Report Generated!")
        unified_compliance_reporter.display_compliance_summary(compliance_report)
        
        # Save structured compliance report
        print(f"\n💾 Saving Structured Compliance Report...")
        compliance_report_path = unified_compliance_reporter.save_compliance_report(
            compliance_report, 
            output_dir="output",
            filename_prefix="structured_compliance_report"
        )
        
        # Show comparison
        print(f"\n📋 Report Comparison:")
        print(f"   📄 Raw Results: {raw_results.get('output_file', 'N/A')}")
        print(f"   📊 Structured Report: {compliance_report_path}")
        
        # Show compliance score
        summary = compliance_report.get_summary()
        print(f"\n🎯 Compliance Score: {summary['compliance_score']}%")
        print(f"   ✅ Passed: {summary['passed']}")
        print(f"   ❌ Failed: {summary['failed']}")
        print(f"   ⚠️  Warnings: {summary['warnings']}")
        print(f"   🔄 Skipped: {summary['skipped']}")
        
    except ImportError as e:
        print(f"❌ Import Error: {e}")
        print("Make sure all required modules are available")
        return 1
    except Exception as e:
        print(f"❌ Error: {e}")
        logger.error(f"Scan failed: {e}", exc_info=True)
        return 1
    
    print(f"\n🎉 Unified compliance scanning with structured reporting completed successfully!")
    return 0

if __name__ == "__main__":
    sys.exit(main())

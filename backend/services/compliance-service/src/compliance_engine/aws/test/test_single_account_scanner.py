#!/usr/bin/env python3
"""
Single Account Direct Compliance Scanner
Tests compliance scanning on current account using direct credentials
"""

import sys
import os
import json
import boto3
from datetime import datetime
import logging

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import service discovery manager for dynamic service loading
try:
    from service_discovery import service_discovery_manager
    SERVICE_DISCOVERY_AVAILABLE = True
except ImportError:
    SERVICE_DISCOVERY_AVAILABLE = False
    # Fallback imports for backward compatibility
    from services.acm.acm_service import ACMService
    from services.account.account_service import AccountService
    from services.accessanalyzer.accessanalyzer_service import AccessAnalyzerService

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SingleAccountScanner:
    """Direct single account compliance scanner"""
    
    def __init__(self):
        self.session = boto3.Session()
        self.scan_start_time = datetime.now()
        self.regions = ['us-east-1', 'us-west-2', 'eu-west-1']  # Default regions
        
    def get_account_info(self):
        """Get current account information"""
        try:
            sts = self.session.client('sts')
            identity = sts.get_caller_identity()
            
            return {
                'account_id': identity.get('Account'),
                'user_arn': identity.get('Arn'),
                'user_id': identity.get('UserId')
            }
        except Exception as e:
            logger.error(f"Failed to get account info: {e}")
            return None
    
    def get_enabled_regions(self):
        """Get enabled regions for current account"""
        try:
            ec2 = self.session.client('ec2', region_name='us-east-1')
            response = ec2.describe_regions()
            enabled_regions = [region['RegionName'] for region in response['Regions']]
            return enabled_regions
        except Exception as e:
            logger.error(f"Failed to get enabled regions: {e}")
            return self.regions  # Fall back to default regions
    
    def scan_service_dynamic(self, service_name, regions=None):
        """Scan any service using dynamic discovery"""
        print(f"\n🔍 Scanning {service_name.upper()} Service...")
        print("-" * 40)
        
        if not SERVICE_DISCOVERY_AVAILABLE:
            print(f"   ❌ Service discovery not available, cannot scan {service_name}")
            return []
        
        if regions is None:
            regions = self.regions
            
        all_findings = []
        
        try:
            # Create service instance using dynamic discovery
            service_instance = service_discovery_manager.create_service_instance(service_name)
            if not service_instance:
                print(f"   ❌ Failed to create {service_name} service instance")
                return []
            
            # Check if service is global or regional
            service_info = service_discovery_manager.get_service_info(service_name)
            is_global = service_info.get('is_global', False)
            
            if is_global:
                # Global service - scan once
                print(f"📍 Scanning {service_name} (global service)...")
                findings = service_instance.run_compliance_checks()
                if findings:
                    all_findings.extend(findings)
                    print(f"   ✅ Found {len(findings)} {service_name} findings")
                else:
                    print(f"   ℹ️  No {service_name} resources found")
            else:
                # Regional service - scan all regions
                for region in regions:
                    try:
                        print(f"📍 Scanning {service_name} in region: {region}")
                        regional_instance = service_discovery_manager.create_service_instance(service_name, region=region)
                        if regional_instance:
                            findings = regional_instance.run_compliance_checks()
                            if findings:
                                all_findings.extend(findings)
                                print(f"   ✅ Found {len(findings)} {service_name} findings in {region}")
                            else:
                                print(f"   ℹ️  No {service_name} resources found in {region}")
                        else:
                            print(f"   ❌ Failed to create {service_name} instance for {region}")
                    except Exception as e:
                        print(f"   ❌ Error scanning {service_name} in {region}: {e}")
                        
        except Exception as e:
            print(f"   ❌ Error scanning {service_name}: {e}")
                
        return all_findings
    
    def scan_acm_service(self, regions=None):
        """Scan ACM service across regions (legacy method)"""
        if SERVICE_DISCOVERY_AVAILABLE:
            return self.scan_service_dynamic('acm', regions)
        else:
            # Fallback to direct import
            print("\n🔍 Scanning ACM Service...")
            print("-" * 40)
            
            if regions is None:
                regions = self.regions
                
            all_findings = []
            
            for region in regions:
                try:
                    print(f"📍 Scanning ACM in region: {region}")
                    acm_service = ACMService(region=region)
                    findings = acm_service.run_compliance_checks()
                    
                    if findings:
                        all_findings.extend(findings)
                        print(f"   ✅ Found {len(findings)} ACM findings in {region}")
                    else:
                        print(f"   ℹ️  No ACM resources found in {region}")
                        
                except Exception as e:
                    print(f"   ❌ Error scanning ACM in {region}: {e}")
                    
            return all_findings
    
    def scan_account_service(self, regions=None):
        """Scan Account service (legacy method)"""
        if SERVICE_DISCOVERY_AVAILABLE:
            return self.scan_service_dynamic('account', regions)
        else:
            # Fallback to direct import
            print("\n🔍 Scanning Account Service...")
            print("-" * 40)
            
            try:
                # Account service is global, so we only need to scan once
                account_service = AccountService(region='us-east-1')
                findings = account_service.run_compliance_checks()
                
                if findings:
                    print(f"   ✅ Found {len(findings)} Account findings")
                    return findings
                else:
                    print(f"   ℹ️  No Account compliance issues found")
                    return []
                    
            except Exception as e:
                print(f"   ❌ Error scanning Account service: {e}")
                return []
    
    def scan_accessanalyzer_service(self, regions=None):
        """Scan AccessAnalyzer service across regions (legacy method)"""
        if SERVICE_DISCOVERY_AVAILABLE:
            return self.scan_service_dynamic('accessanalyzer', regions)
        else:
            # Fallback to direct import
            print("\n🔍 Scanning AccessAnalyzer Service...")
            print("-" * 40)
            
            if regions is None:
                regions = self.regions
                
            all_findings = []
            
            for region in regions:
                try:
                    print(f"📍 Scanning AccessAnalyzer in region: {region}")
                    aa_service = AccessAnalyzerService(region=region)
                    findings = aa_service.run_compliance_checks()
                    
                    if findings:
                        all_findings.extend(findings)
                        print(f"   ✅ Found {len(findings)} AccessAnalyzer findings in {region}")
                    else:
                        print(f"   ℹ️  No AccessAnalyzer resources found in {region}")
                        
                except Exception as e:
                    print(f"   ❌ Error scanning AccessAnalyzer in {region}: {e}")
                    
            return all_findings
    
    def run_single_service_scan(self, service_name, regions=None):
        """Run compliance scan for a single service"""
        print(f"\n🚀 Starting Single Service Scan: {service_name.upper()}")
        print(f"📅 Scan started at: {self.scan_start_time}")
        print("=" * 60)
        
        # Get account info
        account_info = self.get_account_info()
        if account_info:
            print(f"📊 Account ID: {account_info['account_id']}")
            print(f"👤 User: {account_info['user_arn']}")
        
        # Get enabled regions
        if regions is None:
            regions = self.get_enabled_regions()[:3]  # Limit to first 3 regions
            
        print(f"🌍 Scanning regions: {regions}")
        
        # Run service scan
        findings = []
        if service_name.lower() == 'acm':
            findings = self.scan_acm_service(regions)
        elif service_name.lower() == 'account':
            findings = self.scan_account_service(regions)
        elif service_name.lower() == 'accessanalyzer':
            findings = self.scan_accessanalyzer_service(regions)
        else:
            print(f"❌ Unknown service: {service_name}")
            return []
            
        # Display summary
        self._display_scan_summary(service_name, findings, regions)
        
        return findings
    
    def run_all_services_scan(self, regions=None):
        """Run compliance scan for all services using dynamic discovery"""
        print(f"\n🚀 Starting All Services Scan with Dynamic Discovery")
        print(f"📅 Scan started at: {self.scan_start_time}")
        print("=" * 60)
        
        # Get account info
        account_info = self.get_account_info()
        if account_info:
            print(f"📊 Account ID: {account_info['account_id']}")
            print(f"👤 User: {account_info['user_arn']}")
        
        # Get enabled regions
        if regions is None:
            regions = self.get_enabled_regions()[:3]  # Limit to first 3 regions
            
        print(f"🌍 Scanning regions: {regions}")
        
        # Run all service scans
        all_findings = {}
        
        if SERVICE_DISCOVERY_AVAILABLE:
            # Use dynamic service discovery
            discovered_services = service_discovery_manager.get_all_service_names()
            print(f"🔍 Discovered {len(discovered_services)} services: {discovered_services}")
            
            for service_name in discovered_services:
                all_findings[service_name] = self.scan_service_dynamic(service_name, regions)
        else:
            # Fallback to hardcoded services
            print("⚠️  Using fallback hardcoded services")
            all_findings['acm'] = self.scan_acm_service(regions)
            all_findings['account'] = self.scan_account_service(regions)
            all_findings['accessanalyzer'] = self.scan_accessanalyzer_service(regions)
        
        # Display overall summary
        self._display_all_services_summary(all_findings, regions)
        
        return all_findings
    
    def _display_scan_summary(self, service_name, findings, regions):
        """Display scan summary for single service"""
        print(f"\n📊 {service_name.upper()} Scan Summary")
        print("-" * 40)
        print(f"🌍 Regions scanned: {len(regions)}")
        print(f"🔍 Total findings: {len(findings)}")
        
        if findings:
            # Group by status
            status_counts = {}
            for finding in findings:
                status = finding.get('ComplianceStatus', 'UNKNOWN')
                status_counts[status] = status_counts.get(status, 0) + 1
            
            print(f"📋 Findings by status:")
            for status, count in status_counts.items():
                emoji = "✅" if status == "PASS" else "❌" if status == "FAIL" else "⚠️"
                print(f"   {emoji} {status}: {count}")
            
            # Show sample findings
            print(f"\n📋 Sample findings (first 3):")
            for i, finding in enumerate(findings[:3]):
                check_name = finding.get('CheckName', 'Unknown')
                status = finding.get('ComplianceStatus', 'UNKNOWN')
                emoji = "✅" if status == "PASS" else "❌" if status == "FAIL" else "⚠️"
                print(f"   {i+1}. {emoji} {check_name}: {status}")
    
    def _display_all_services_summary(self, all_findings, regions):
        """Display summary for all services scan"""
        print(f"\n📊 All Services Scan Summary")
        print("=" * 60)
        print(f"🌍 Regions scanned: {len(regions)}")
        
        total_findings = 0
        for service, findings in all_findings.items():
            count = len(findings)
            total_findings += count
            print(f"🔍 {service.upper()}: {count} findings")
        
        print(f"📈 Total findings across all services: {total_findings}")
        
        # Show service breakdown
        print(f"\n📋 Service Breakdown:")
        for service, findings in all_findings.items():
            if findings:
                status_counts = {}
                for finding in findings:
                    status = finding.get('ComplianceStatus', 'UNKNOWN')
                    status_counts[status] = status_counts.get(status, 0) + 1
                
                print(f"   {service.upper()}:")
                for status, count in status_counts.items():
                    emoji = "✅" if status == "PASS" else "❌" if status == "FAIL" else "⚠️"
                    print(f"     {emoji} {status}: {count}")
    
    def save_results(self, results, service_name="all"):
        """Save scan results to JSON file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"single_account_scan_{service_name}_{timestamp}.json"
        
        scan_data = {
            "scan_type": "single_account",
            "service": service_name,
            "timestamp": timestamp,
            "account_info": self.get_account_info(),
            "regions": self.regions,
            "findings": results
        }
        
        with open(filename, 'w') as f:
            json.dump(scan_data, f, indent=2, default=str)
        
        print(f"💾 Results saved to: {filename}")

def main():
    """Main function with interactive menu"""
    scanner = SingleAccountScanner()
    
    print("🔍 Single Account Compliance Scanner")
    print("=" * 60)
    print("Note: This scanner uses your current AWS credentials directly")
    print("No cross-account role assumptions required")
    print()
    
    while True:
        print("📋 Choose scanning option:")
        print("1. 🔍 Scan ACM Service")
        print("2. 🏢 Scan Account Service")
        print("3. 🔒 Scan AccessAnalyzer Service")
        print("4. 🌍 Scan All Services")
        print("5. 🚪 Exit")
        
        choice = input("\nEnter your choice (1-5): ").strip()
        
        if choice == '1':
            findings = scanner.run_single_service_scan('acm')
            if findings:
                save_choice = input("\nSave results? (y/n): ").strip().lower()
                if save_choice == 'y':
                    scanner.save_results(findings, 'acm')
                    
        elif choice == '2':
            findings = scanner.run_single_service_scan('account')
            if findings:
                save_choice = input("\nSave results? (y/n): ").strip().lower()
                if save_choice == 'y':
                    scanner.save_results(findings, 'account')
                    
        elif choice == '3':
            findings = scanner.run_single_service_scan('accessanalyzer')
            if findings:
                save_choice = input("\nSave results? (y/n): ").strip().lower()
                if save_choice == 'y':
                    scanner.save_results(findings, 'accessanalyzer')
                    
        elif choice == '4':
            findings = scanner.run_all_services_scan()
            if findings:
                save_choice = input("\nSave results? (y/n): ").strip().lower()
                if save_choice == 'y':
                    scanner.save_results(findings, 'all')
                    
        elif choice == '5':
            print("👋 Goodbye!")
            break
            
        else:
            print("❌ Invalid choice. Please try again.")
            
        input("\nPress Enter to continue...")

if __name__ == "__main__":
    main()
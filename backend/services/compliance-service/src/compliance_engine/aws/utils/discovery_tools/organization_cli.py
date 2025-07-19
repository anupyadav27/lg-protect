#!/usr/bin/env python3
"""
Organization CLI - Single file for all organization functionality
Handles multi-account discovery, configuration, and compliance scanning
"""

import sys
import os
import json
import boto3
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

# Add parent directories to path
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

class OrganizationCLI:
    """Single CLI for all organization functionality"""
    
    def __init__(self, config_file: str = "config/multi_account_config.json"):
        self.config_file = config_file
        self.config = self.load_config()
        self.master_session = boto3.Session()
        self.account_sessions = {}
        self.organization_structure = None
        
    def load_config(self) -> Dict[str, Any]:
        """Load multi-account configuration"""
        try:
            config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), self.config_file)
            with open(config_path, 'r') as f:
                data = json.load(f)
                config = data.get('multi_account_configuration', {})
                logger.info(f"✅ Config loaded: {len(config.get('account_overrides', {}))} accounts")
                return config
        except Exception as e:
            logger.error(f"❌ Failed to load config: {e}")
            return {}
    
    def discover_organization_structure(self) -> Dict[str, Any]:
        """Discover AWS organization structure"""
        try:
            org_client = self.master_session.client('organizations')
            
            # Get organization details
            org_response = org_client.describe_organization()
            org_details = org_response['Organization']
            
            # Get all accounts
            accounts_response = org_client.list_accounts()
            accounts = accounts_response['Accounts']
            
            # Build organization structure
            self.organization_structure = {
                'organization_id': org_details['Id'],
                'master_account_id': org_details['MasterAccountId'],
                'master_account_email': org_details['MasterAccountEmail'],
                'feature_set': org_details['FeatureSet'],
                'total_accounts': len(accounts),
                'active_accounts': len([acc for acc in accounts if acc['Status'] == 'ACTIVE']),
                'accounts': accounts
            }
            
            logger.info(f"✅ Discovered organization: {len(accounts)} accounts")
            return self.organization_structure
            
        except Exception as e:
            logger.error(f"❌ Failed to discover organization: {e}")
            return {}
    
    def get_account_session(self, account_id: str) -> Optional[boto3.Session]:
        """Get or create session for account"""
        if account_id in self.account_sessions:
            return self.account_sessions[account_id]
        
        if not self.config:
            return None
            
        # Get account config
        account_config = self.config.get('account_overrides', {}).get(account_id)
        if not account_config or not account_config.get('enabled', True):
            return None
        
        # If master account, use current session
        if account_id == self.config.get('master_account_id'):
            self.account_sessions[account_id] = self.master_session
            return self.master_session
        
        # Assume role for member accounts
        try:
            role_name = account_config.get('role_name', 'OrganizationAccountAccessRole')
            role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
            
            sts = self.master_session.client('sts')
            response = sts.assume_role(
                RoleArn=role_arn,
                RoleSessionName=f"OrgCLI-{account_id}-{datetime.now().strftime('%Y%m%d%H%M%S')}"
            )
            
            session = boto3.Session(
                aws_access_key_id=response['Credentials']['AccessKeyId'],
                aws_secret_access_key=response['Credentials']['SecretAccessKey'],
                aws_session_token=response['Credentials']['SessionToken']
            )
            
            self.account_sessions[account_id] = session
            logger.info(f"✅ Created session for {account_config['account_name']} ({account_id})")
            return session
            
        except Exception as e:
            logger.error(f"❌ Failed to assume role for {account_id}: {e}")
            return None
    
    def discover_enabled_regions(self, account_id: str) -> List[str]:
        """Discover enabled regions for an account"""
        session = self.get_account_session(account_id)
        if not session:
            return []
        
        try:
            ec2_client = session.client('ec2', region_name='us-east-1')
            response = ec2_client.describe_regions()
            
            enabled_regions = []
            for region in response['Regions']:
                region_name = region['RegionName']
                opt_in_status = region.get('OptInStatus', 'opt-in-not-required')
                
                if opt_in_status in ['opt-in-not-required', 'opted-in']:
                    enabled_regions.append(region_name)
            
            logger.info(f"✅ Found {len(enabled_regions)} enabled regions for account {account_id}")
            return enabled_regions
            
        except Exception as e:
            logger.error(f"❌ Failed to discover regions for account {account_id}: {e}")
            return ['us-east-1']  # Fallback to default region
    
    def discover_all_accounts_regions(self) -> Dict[str, List[str]]:
        """Discover enabled regions for all accounts"""
        logger.info("🌍 Discovering enabled regions for all accounts...")
        
        if not self.config:
            return {}
        
        enabled_accounts = {
            account_id: config for account_id, config in self.config.get('account_overrides', {}).items()
            if config.get('enabled', True)
        }
        
        account_regions = {}
        
        for account_id, account_config in enabled_accounts.items():
            account_name = account_config.get('account_name', account_id)
            logger.info(f"🔍 Discovering regions for {account_name} ({account_id})...")
            
            enabled_regions = self.discover_enabled_regions(account_id)
            
            # Apply region limit if configured
            region_limit = self.config.get('regions', {}).get('region_limit', 0)
            if region_limit > 0 and len(enabled_regions) > region_limit:
                enabled_regions = enabled_regions[:region_limit]
                logger.info(f"⚠️ Limited to {region_limit} regions for {account_name}")
            
            account_regions[account_id] = enabled_regions
            logger.info(f"📍 {account_name}: {len(enabled_regions)} regions - {enabled_regions}")
        
        return account_regions
    
    def scan_account_service(self, account_id: str, service_name: str, regions: List[str]) -> List[Dict]:
        """Scan a specific service in an account across regions using dynamic discovery"""
        session = self.get_account_session(account_id)
        if not session:
            return []
        
        all_findings = []
        
        if SERVICE_DISCOVERY_AVAILABLE:
            # Use dynamic service discovery
            try:
                # Create service instance using dynamic discovery
                service_instance = service_discovery_manager.create_service_instance(service_name, session=session)
                if not service_instance:
                    logger.error(f"❌ Failed to create {service_name} service instance")
                    return []
                
                # Get service info to determine if it's global or regional
                service_info = service_discovery_manager.get_service_info(service_name)
                is_global = service_info.get('is_global', False)
                
                if is_global:
                    # Global service - scan once
                    logger.info(f"🔍 Scanning {service_name} (global service) in {account_id}")
                    findings = service_instance.run_compliance_checks()
                    if findings:
                        # Add account and region info to findings
                        for finding in findings:
                            finding['account_id'] = account_id
                            finding['region'] = 'us-east-1'  # Global services typically use us-east-1
                            finding['service'] = service_name
                        all_findings.extend(findings)
                else:
                    # Regional service - scan all regions
                    for region in regions:
                        try:
                            logger.info(f"🔍 Scanning {service_name} in {account_id}/{region}")
                            regional_instance = service_discovery_manager.create_service_instance(service_name, session=session, region=region)
                            if regional_instance:
                                findings = regional_instance.run_compliance_checks()
                                if findings:
                                    # Add account and region info to findings
                                    for finding in findings:
                                        finding['account_id'] = account_id
                                        finding['region'] = region
                                        finding['service'] = service_name
                                    all_findings.extend(findings)
                        except Exception as e:
                            logger.error(f"❌ Error scanning {service_name} in {account_id}/{region}: {e}")
                            
            except Exception as e:
                logger.error(f"❌ Error with dynamic service discovery for {service_name}: {e}")
        else:
            # Fallback to hardcoded services
            for region in regions:
                try:
                    if service_name == 'acm':
                        service = ACMService(region=region, session=session)
                    elif service_name == 'account':
                        service = AccountService(region=region, session=session)
                    elif service_name == 'accessanalyzer':
                        service = AccessAnalyzerService(region=region, session=session)
                    else:
                        continue
                    
                    findings = service.run_compliance_checks()
                    if findings:
                        # Add account and region info to findings
                        for finding in findings:
                            finding['account_id'] = account_id
                            finding['region'] = region
                            finding['service'] = service_name
                        all_findings.extend(findings)
                        
                except Exception as e:
                    logger.error(f"❌ Error scanning {service_name} in {account_id}/{region}: {e}")
        
        return all_findings
    
    def scan_single_account(self, account_id: str, regions: Optional[List[str]] = None) -> Dict[str, List[Dict]]:
        """Scan all services in a single account"""
        if not self.config:
            return {}
            
        account_config = self.config.get('account_overrides', {}).get(account_id)
        if not account_config or not account_config.get('enabled', True):
            logger.info(f"⏭️ Skipping disabled account {account_id}")
            return {}
        
        account_name = account_config.get('account_name', account_id)
        
        # Use provided regions or discover them
        if regions is None:
            regions = self.discover_enabled_regions(account_id)
        
        # Get services to scan using dynamic discovery
        if SERVICE_DISCOVERY_AVAILABLE:
            services = service_discovery_manager.get_all_service_names()
            logger.info(f"🔍 Using dynamic service discovery: {len(services)} services available")
        else:
            services = self.config.get('services_to_scan', ['acm', 'account', 'accessanalyzer'])
            logger.info(f"⚠️ Using fallback hardcoded services: {services}")
        
        logger.info(f"🔍 Scanning {account_name} ({account_id}) - {len(regions)} regions, {len(services)} services")
        
        results = {}
        for service in services:
            findings = self.scan_account_service(account_id, service, regions)
            results[service] = findings
            logger.info(f"  ✅ {service.upper()}: {len(findings)} findings")
        
        return results
    
    def scan_all_accounts(self, discover_regions: bool = False) -> Dict[str, Any]:
        """Scan all enabled accounts"""
        if not self.config:
            logger.error("❌ No configuration loaded")
            return {}
        
        enabled_accounts = {
            account_id: config for account_id, config in self.config.get('account_overrides', {}).items()
            if config.get('enabled', True)
        }
        
        logger.info(f"🚀 Starting multi-account scan: {len(enabled_accounts)} accounts")
        
        # Discover regions if requested
        account_regions = {}
        if discover_regions:
            account_regions = self.discover_all_accounts_regions()
        
        all_results = {}
        total_findings = 0
        
        # Use ThreadPoolExecutor for parallel scanning
        max_workers = self.config.get('parallel_execution', {}).get('max_workers', 3)
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_account = {}
            
            for account_id in enabled_accounts.keys():
                regions = account_regions.get(account_id) if discover_regions else None
                future = executor.submit(self.scan_single_account, account_id, regions)
                future_to_account[future] = account_id
            
            # Collect results
            for future in as_completed(future_to_account):
                account_id = future_to_account[future]
                try:
                    account_results = future.result()
                    all_results[account_id] = account_results
                    
                    # Count findings
                    account_total = sum(len(findings) for findings in account_results.values())
                    total_findings += account_total
                    
                    account_name = enabled_accounts[account_id].get('account_name', account_id)
                    logger.info(f"✅ Completed {account_name}: {account_total} findings")
                    
                except Exception as e:
                    logger.error(f"❌ Failed to scan account {account_id}: {e}")
                    all_results[account_id] = {'error': str(e)}
        
        logger.info(f"🎉 Multi-account scan completed: {total_findings} total findings")
        return all_results
    
    def display_organization_summary(self):
        """Display organization structure summary"""
        if not self.organization_structure:
            org_data = self.discover_organization_structure()
            if not org_data:
                print("❌ Failed to discover organization structure")
                return
        
        # At this point, organization_structure should be available
        org_structure = self.organization_structure
        if not org_structure:
            print("❌ Organization structure is still not available")
            return
        
        print("\n📊 Organization Structure Summary:")
        print("-" * 50)
        print(f"🏢 Organization ID: {org_structure.get('organization_id', 'Unknown')}")
        print(f"👤 Master Account: {org_structure.get('master_account_id', 'Unknown')}")
        print(f"📧 Master Email: {org_structure.get('master_account_email', 'Unknown')}")
        print(f"🔧 Feature Set: {org_structure.get('feature_set', 'Unknown')}")
        print(f"📊 Total Accounts: {org_structure.get('total_accounts', 0)}")
        print(f"✅ Active Accounts: {org_structure.get('active_accounts', 0)}")
        
        print(f"\n📋 Account Details:")
        accounts = org_structure.get('accounts', [])
        for account in accounts:
            status_emoji = "✅" if account.get('Status') == "ACTIVE" else "❌"
            print(f"  {status_emoji} {account.get('Name', 'Unknown')} ({account.get('Id', 'Unknown')})")
            print(f"    Email: {account.get('Email', 'Unknown')}")
            print(f"    Status: {account.get('Status', 'Unknown')}")
            print(f"    Joined: {account.get('JoinedTimestamp', 'Unknown')}")
            print()
    
    def display_config_summary(self):
        """Display configuration summary"""
        if not self.config:
            print("❌ No configuration loaded")
            return
        
        print(f"\n📊 Configuration Summary:")
        print("-" * 50)
        print(f"🏢 Organization: {self.config.get('organization_id')}")
        print(f"👤 Master Account: {self.config.get('master_account_id')}")
        print(f"🔑 Default Role: {self.config.get('default_cross_account_role')}")
        
        accounts = self.config.get('account_overrides', {})
        print(f"👥 Configured Accounts: {len(accounts)}")
        
        for account_id, config in accounts.items():
            status = "✅" if config.get('enabled', True) else "❌"
            regions = len(config.get('regions', []))
            print(f"  {status} {config.get('account_name', account_id)} ({account_id})")
            print(f"    Role: {config.get('role_name', 'OrganizationAccountAccessRole')}")
            print(f"    Regions: {regions} configured")
            if config.get('notes'):
                print(f"    Notes: {config.get('notes')}")
            print()
    
    def display_results_summary(self, results: Dict[str, Any]):
        """Display scan results summary"""
        if not results:
            print("❌ No results to display")
            return
        
        print("\n📊 Multi-Account Compliance Scan Results")
        print("=" * 60)
        
        total_findings = 0
        successful_accounts = 0
        failed_accounts = 0
        
        for account_id, account_results in results.items():
            account_config = self.config.get('account_overrides', {}).get(account_id, {})
            account_name = account_config.get('account_name', account_id)
            
            if 'error' in account_results:
                failed_accounts += 1
                print(f"❌ {account_name} ({account_id}): {account_results['error']}")
            else:
                successful_accounts += 1
                account_total = sum(len(findings) for findings in account_results.values())
                total_findings += account_total
                
                print(f"✅ {account_name} ({account_id}): {account_total} findings")
                
                # Show service breakdown
                for service, findings in account_results.items():
                    if findings:
                        print(f"   {service.upper()}: {len(findings)} findings")
        
        print(f"\n📈 Summary:")
        print(f"✅ Successful accounts: {successful_accounts}")
        print(f"❌ Failed accounts: {failed_accounts}")
        print(f"🔍 Total findings: {total_findings}")
    
    def save_results(self, results: Dict[str, Any], filename: Optional[str] = None):
        """Save results to JSON file"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"organization_scan_results_{timestamp}.json"
        
        scan_data = {
            "scan_type": "organization_multi_account",
            "timestamp": timestamp,
            "organization_id": self.config.get('organization_id'),
            "master_account": self.config.get('master_account_id'),
            "scanned_accounts": len(results),
            "results": results
        }
        
        with open(filename, 'w') as f:
            json.dump(scan_data, f, indent=2, default=str)
        
        print(f"💾 Results saved to: {filename}")

def main():
    """Main CLI function"""
    print("🏢 AWS Organization CLI - Multi-Account Compliance Scanner")
    print("=" * 70)
    
    org_cli = OrganizationCLI()
    
    if not org_cli.config:
        print("❌ Failed to load configuration")
        return
    
    while True:
        print("\n📋 Choose an option:")
        print("1. 🏢 Discover Organization Structure")
        print("2. 🔍 Discover Enabled Regions for All Accounts")
        print("3. 📊 View Configuration Summary")
        print("4. 🔍 Scan Single Account")
        print("5. 🌍 Scan All Accounts (configured regions)")
        print("6. 🔄 Scan All Accounts (discover regions)")
        print("7. 🚪 Exit")
        
        choice = input("\nEnter your choice (1-7): ").strip()
        
        if choice == '1':
            org_cli.display_organization_summary()
        
        elif choice == '2':
            account_regions = org_cli.discover_all_accounts_regions()
            if account_regions:
                print(f"\n🌍 Discovered regions for {len(account_regions)} accounts:")
                for account_id, regions in account_regions.items():
                    account_name = org_cli.config.get('account_overrides', {}).get(account_id, {}).get('account_name', account_id)
                    print(f"  📍 {account_name} ({account_id}): {len(regions)} regions")
                    print(f"    Regions: {regions}")
        
        elif choice == '3':
            org_cli.display_config_summary()
        
        elif choice == '4':
            accounts = org_cli.config.get('account_overrides', {})
            print(f"\n📋 Available accounts:")
            for i, (account_id, config) in enumerate(accounts.items(), 1):
                status = "✅" if config.get('enabled', True) else "❌"
                print(f"  {i}. {status} {config.get('account_name', account_id)} ({account_id})")
            
            account_choice = input(f"\nEnter account number (1-{len(accounts)}): ").strip()
            
            if account_choice.isdigit():
                idx = int(account_choice) - 1
                account_list = list(accounts.keys())
                if 0 <= idx < len(account_list):
                    account_id = account_list[idx]
                    results = org_cli.scan_single_account(account_id)
                    
                    if results:
                        account_name = accounts[account_id].get('account_name', account_id)
                        print(f"\n✅ Scan completed for {account_name}")
                        
                        total = sum(len(findings) for findings in results.values())
                        print(f"📊 Total findings: {total}")
                        
                        for service, findings in results.items():
                            print(f"  {service.upper()}: {len(findings)} findings")
                        
                        save_choice = input("\nSave results? (y/n): ").strip().lower()
                        if save_choice == 'y':
                            org_cli.save_results({account_id: results})
                    else:
                        print("❌ Scan failed or no results")
                else:
                    print("❌ Invalid account number")
            else:
                print("❌ Invalid input")
        
        elif choice == '5':
            print("\n🌍 Starting multi-account scan with configured regions...")
            results = org_cli.scan_all_accounts(discover_regions=False)
            
            if results:
                org_cli.display_results_summary(results)
                
                save_choice = input("\nSave results? (y/n): ").strip().lower()
                if save_choice == 'y':
                    org_cli.save_results(results)
            else:
                print("❌ Scan failed")
        
        elif choice == '6':
            print("\n🔄 Starting multi-account scan with region discovery...")
            results = org_cli.scan_all_accounts(discover_regions=True)
            
            if results:
                org_cli.display_results_summary(results)
                
                save_choice = input("\nSave results? (y/n): ").strip().lower()
                if save_choice == 'y':
                    org_cli.save_results(results)
            else:
                print("❌ Scan failed")
        
        elif choice == '7':
            print("👋 Goodbye!")
            break
        
        else:
            print("❌ Invalid choice. Please try again.")
        
        input("\nPress Enter to continue...")

if __name__ == "__main__":
    main()
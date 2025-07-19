#!/usr/bin/env python3
"""
Account, Region, and Service Discovery Manager

Completely dynamic discovery manager that discovers accounts, regions, and services
without any hardcoded fallbacks. Scales automatically as new services are added.
"""

import boto3
import json
import logging
import os
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

# Import dynamic service discovery from organization folder
try:
    from .service_discovery import ServiceDiscoveryManager
    SERVICE_DISCOVERY_AVAILABLE = True
except ImportError:
    SERVICE_DISCOVERY_AVAILABLE = False
    print("⚠️  Service discovery not available - will use minimal fallback")

logger = logging.getLogger(__name__)

class AccountSessionManager:
    """Manages AWS sessions for different accounts"""
    
    def __init__(self, config: Dict[str, Any], discovered_accounts: Optional[List[Dict[str, Any]]] = None):
        self.config = config
        self.discovered_accounts = discovered_accounts or []
        self.account_sessions = {}
    
    def get_account_session(self, account_id: str) -> Optional[boto3.Session]:
        """Get session for specific account"""
        if account_id in self.account_sessions:
            return self.account_sessions[account_id]
        
        try:
            # Check if this is the master account
            if account_id == self.config.get('master_account_id'):
                session = boto3.Session()
            else:
                # Use cross-account role assumption
                role_arn = self._get_role_for_account(account_id)
                session = self._assume_role_session(role_arn, account_id)
            
            self.account_sessions[account_id] = session
            return session
            
        except Exception as e:
            logger.error(f"❌ Failed to create session for account {account_id}: {e}")
            return None
    
    def _assume_role_session(self, role_arn: str, account_id: str) -> boto3.Session:
        """Assume cross-account role and create session"""
        try:
            sts_client = boto3.client('sts')
            assumed_role = sts_client.assume_role(
                RoleArn=role_arn,
                RoleSessionName=f"compliance-scan-{account_id}"
            )
            
            credentials = assumed_role['Credentials']
            return boto3.Session(
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken']
            )
        except Exception as e:
            logger.error(f"❌ Failed to assume role {role_arn}: {e}")
            raise
    
    def _get_role_for_account(self, account_id: str) -> str:
        """Get role ARN for account from config or use default pattern"""
        account_overrides = self.config.get('account_overrides', {})
        if account_id in account_overrides:
            custom_role = account_overrides[account_id].get('role_arn')
            if custom_role:
                return custom_role
        
        # Use default role pattern
        return f"arn:aws:iam::{account_id}:role/ComplianceScanRole"

class RegionDiscoveryManager:
    """Discovers enabled regions for accounts"""
    
    def __init__(self, session_manager: AccountSessionManager):
        self.session_manager = session_manager
        self.region_cache = {}
    
    def discover_enabled_regions(self, account_id: str) -> List[str]:
        """Discover enabled regions for account"""
        if account_id in self.region_cache:
            return self.region_cache[account_id]
        
        try:
            session = self.session_manager.get_account_session(account_id)
            if not session:
                logger.warning(f"⚠️ No session available for account {account_id}")
                return []
            
            ec2_client = session.client('ec2')
            response = ec2_client.describe_regions(
                Filters=[{'Name': 'opt-in-status', 'Values': ['opt-in-not-required', 'opted-in']}]
            )
            
            regions = [region['RegionName'] for region in response['Regions']]
            self.region_cache[account_id] = regions
            
            logger.info(f"✅ Discovered {len(regions)} regions for account {account_id}")
            return regions
            
        except Exception as e:
            logger.error(f"❌ Failed to discover regions for account {account_id}: {e}")
            return []
    
    def discover_all_accounts_regions(self, discovered_accounts: List[Dict[str, Any]]) -> Dict[str, List[str]]:
        """Discover enabled regions for all accounts in parallel"""
        account_regions = {}
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            future_to_account = {
                executor.submit(self.discover_enabled_regions, account['Id']): account['Id']
                for account in discovered_accounts
            }
            
            for future in as_completed(future_to_account):
                account_id = future_to_account[future]
                try:
                    regions = future.result()
                    account_regions[account_id] = regions
                except Exception as e:
                    logger.error(f"❌ Error discovering regions for account {account_id}: {e}")
                    account_regions[account_id] = []
        
        return account_regions

class OrganizationDiscoveryManager:
    """Discovers AWS organization structure"""
    
    def __init__(self, master_session: boto3.Session):
        self.master_session = master_session
        self.org_client = master_session.client('organizations')
    
    def discover_organization_structure(self) -> Dict[str, Any]:
        """Discover complete organization structure"""
        try:
            # Get organization details
            org_details = self.org_client.describe_organization()['Organization']
            
            # Get all accounts
            accounts = []
            paginator = self.org_client.get_paginator('list_accounts')
            
            for page in paginator.paginate():
                accounts.extend(page['Accounts'])
            
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

class ScanTarget:
    """Represents a single scan target (account + region + service)"""
    
    def __init__(self, account_id: str, account_name: str, region: str, service_name: str):
        self.account_id = account_id
        self.account_name = account_name
        self.region = region
        self.service_name = service_name
        self.scan_id = f"{account_id}_{region}_{service_name}"
        self.status = "pending"
        self.start_time = None
        self.end_time = None
        self.results = None
        self.error = None
    
    def __str__(self):
        return f"{self.account_name}({self.account_id})/{self.region}/{self.service_name}"
    
    def to_dict(self):
        return {
            'scan_id': self.scan_id,
            'account_id': self.account_id,
            'account_name': self.account_name,
            'region': self.region,
            'service_name': self.service_name,
            'status': self.status,
            'start_time': self.start_time,
            'end_time': self.end_time,
            'error': self.error
        }

class ScanStatistics:
    """Tracks scan execution statistics"""
    
    def __init__(self):
        self.total_targets = 0
        self.completed_targets = 0
        self.failed_targets = 0
        self.pending_targets = 0
        self.start_time = None
        self.end_time = None
        self.service_results = {}
        self.account_results = {}
        self.region_results = {}
    
    def update_progress(self, target: ScanTarget):
        """Update statistics based on target completion"""
        if target.status == "completed":
            self.completed_targets += 1
            self.pending_targets -= 1
        elif target.status == "failed":
            self.failed_targets += 1
            self.pending_targets -= 1
        
        # Update service results
        if target.service_name not in self.service_results:
            self.service_results[target.service_name] = {'completed': 0, 'failed': 0}
        
        if target.status == "completed":
            self.service_results[target.service_name]['completed'] += 1
        elif target.status == "failed":
            self.service_results[target.service_name]['failed'] += 1
        
        # Update account results
        if target.account_id not in self.account_results:
            self.account_results[target.account_id] = {'completed': 0, 'failed': 0}
        
        if target.status == "completed":
            self.account_results[target.account_id]['completed'] += 1
        elif target.status == "failed":
            self.account_results[target.account_id]['failed'] += 1
    
    def get_progress_percentage(self) -> float:
        """Get completion percentage"""
        if self.total_targets == 0:
            return 0.0
        return (self.completed_targets + self.failed_targets) / self.total_targets * 100
    
    def get_elapsed_time(self) -> float:
        """Get elapsed time in seconds"""
        if not self.start_time:
            return 0.0
        end_time = self.end_time or datetime.now()
        return (end_time - self.start_time).total_seconds()
    
    def to_dict(self):
        return {
            'total_targets': self.total_targets,
            'completed_targets': self.completed_targets,
            'failed_targets': self.failed_targets,
            'pending_targets': self.pending_targets,
            'progress_percentage': self.get_progress_percentage(),
            'elapsed_time_seconds': self.get_elapsed_time(),
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'service_results': self.service_results,
            'account_results': self.account_results
        }

class AccountRegionServiceDiscoveryManager:
    """
    Enhanced discovery manager with complete dynamic discovery
    No hardcoded fallbacks - scales automatically with new services
    """
    
    def __init__(self, config_file: str = "config/multi_account_config.json"):
        self.config_file = config_file
        self.config = self._load_config()
        
        # Initialize dynamic service discovery
        if SERVICE_DISCOVERY_AVAILABLE:
            self.service_discovery = ServiceDiscoveryManager()
            logger.info("✅ Dynamic service discovery initialized")
        else:
            self.service_discovery = None
            logger.warning("⚠️ Dynamic service discovery not available")
        
        # Initialize discovery managers
        self.org_manager = OrganizationDiscoveryManager(boto3.Session())
        
        # Discover organization structure
        self.org_structure = self.org_manager.discover_organization_structure()
        self.discovered_accounts = self.org_structure.get('accounts', []) if self.org_structure else []
        
        # Initialize session and region managers
        self.session_manager = AccountSessionManager(self.config, self.discovered_accounts)
        self.region_manager = RegionDiscoveryManager(self.session_manager)
        
        # Output directory
        self.output_dir = Path("output")
        self.output_dir.mkdir(exist_ok=True)
        
        # Scan tracking
        self.current_scan = None
        self.scan_statistics = None
    
    def _load_config(self) -> Dict[str, Any]:
        """Load multi-account configuration"""
        try:
            config_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), self.config_file)
            with open(config_path, 'r') as f:
                data = json.load(f)
                config = data.get('multi_account_configuration', {})
                logger.info(f"✅ Config loaded with {len(config.get('account_overrides', {}))} account overrides")
                return config
        except Exception as e:
            logger.error(f"❌ Failed to load config: {e}")
            return {}
    
    def get_all_scan_targets(self, requested_services: List[str] = None, 
                           requested_accounts: List[str] = None,
                           requested_regions: List[str] = None) -> List[ScanTarget]:
        """
        Generate all scan targets dynamically
        
        Args:
            requested_services: Specific services to scan (None = all discovered)
            requested_accounts: Specific accounts to scan (None = all active)
            requested_regions: Specific regions to scan (None = all enabled)
            
        Returns:
            List of scan targets
        """
        targets = []
        
        # Get services to scan
        if self.service_discovery:
            available_services = self.service_discovery.get_all_service_names()
            if requested_services:
                services_to_scan = [s for s in requested_services if s in available_services]
                logger.info(f"🔍 Filtered to {len(services_to_scan)} requested services from {len(available_services)} available")
            else:
                services_to_scan = available_services
                logger.info(f"🔍 Using all {len(services_to_scan)} discovered services")
        else:
            logger.error("❌ Service discovery not available - cannot generate scan targets")
            return []
        
        # Get accounts to scan
        active_accounts = self.get_active_accounts()
        if requested_accounts:
            accounts_to_scan = [acc for acc in active_accounts if acc['Id'] in requested_accounts]
            logger.info(f"🏢 Filtered to {len(accounts_to_scan)} requested accounts from {len(active_accounts)} active")
        else:
            accounts_to_scan = active_accounts
            logger.info(f"🏢 Using all {len(accounts_to_scan)} active accounts")
        
        # Generate targets for each account
        for account in accounts_to_scan:
            account_id = account['Id']
            account_name = account['Name']
            
            # Discover regions for this account
            account_regions = self.region_manager.discover_enabled_regions(account_id)
            if requested_regions:
                regions_to_scan = [r for r in account_regions if r in requested_regions]
            else:
                regions_to_scan = account_regions
            
            logger.info(f"🌍 Account {account_name}: {len(regions_to_scan)} regions available")
            
            # Create scan targets for each service-region combination
            for service_name in services_to_scan:
                for region in regions_to_scan:
                    target = ScanTarget(account_id, account_name, region, service_name)
                    targets.append(target)
        
        logger.info(f"🎯 Generated {len(targets)} scan targets")
        return targets
    
    def execute_scan_target(self, target: ScanTarget) -> Dict[str, Any]:
        """
        Execute a single scan target
        
        Args:
            target: ScanTarget to execute
            
        Returns:
            Scan results for this target
        """
        target.status = "running"
        target.start_time = datetime.now()
        
        try:
            # Get account session
            account_session = self.session_manager.get_account_session(target.account_id)
            if not account_session:
                raise Exception(f"No session available for account {target.account_id}")
            
            # Create service instance
            if not self.service_discovery:
                raise Exception("Service discovery not available")
            
            service_instance = self.service_discovery.create_service_instance(
                target.service_name, account_session, target.region
            )
            if not service_instance:
                raise Exception(f"Failed to create service instance for {target.service_name}")
            
            # Run compliance checks
            results = service_instance.run_compliance_checks(target.region)
            
            # Add metadata to results
            for result in results:
                result.update({
                    'account_id': target.account_id,
                    'account_name': target.account_name,
                    'region': target.region,
                    'service': target.service_name,
                    'timestamp': datetime.now().isoformat()
                })
            
            target.status = "completed"
            target.results = results
            target.end_time = datetime.now()
            
            logger.info(f"✅ Completed scan: {target}")
            return {
                'target': target.to_dict(),
                'results': results,
                'success': True
            }
            
        except Exception as e:
            target.status = "failed"
            target.error = str(e)
            target.end_time = datetime.now()
            
            logger.error(f"❌ Failed scan: {target} - {e}")
            return {
                'target': target.to_dict(),
                'error': str(e),
                'success': False
            }
    
    def execute_parallel_scan(self, targets: List[ScanTarget], max_workers: int = 10) -> Dict[str, Any]:
        """
        Execute multiple scan targets in parallel
        
        Args:
            targets: List of scan targets to execute
            max_workers: Maximum number of parallel workers
            
        Returns:
            Complete scan results
        """
        logger.info(f"🚀 Starting parallel execution of {len(targets)} scan targets using {max_workers} workers")
        
        # Initialize scan statistics
        self.scan_statistics = ScanStatistics()
        self.scan_statistics.total_targets = len(targets)
        self.scan_statistics.pending_targets = len(targets)
        self.scan_statistics.start_time = datetime.now()
        
        results = {
            'scan_id': f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            'start_time': datetime.now().isoformat(),
            'targets': [],
            'summary': {},
            'errors': []
        }
        
        # Execute targets in parallel
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_target = {
                executor.submit(self.execute_scan_target, target): target
                for target in targets
            }
            
            for future in as_completed(future_to_target):
                target = future_to_target[future]
                
                try:
                    result = future.result()
                    results['targets'].append(result)
                    
                    # Update statistics
                    self.scan_statistics.update_progress(target)
                    
                    # Log progress
                    completed = len([r for r in results['targets'] if r.get('success', False)])
                    failed = len([r for r in results['targets'] if not r.get('success', False)])
                    total = len(results['targets'])
                    progress = self.scan_statistics.get_progress_percentage()
                    logger.info(f"📊 Progress: {completed + failed}/{total} targets completed ({progress:.1f}%)")
                    
                except Exception as e:
                    logger.error(f"❌ Unexpected error processing target {target}: {e}")
                    results['errors'].append({
                        'target': target.to_dict(),
                        'error': str(e)
                    })
        
        # Finalize results
        self.scan_statistics.end_time = datetime.now()
        results['end_time'] = datetime.now().isoformat()
        results['summary'] = self._generate_scan_summary(results)
        
        logger.info(f"✅ Scan execution completed in {self.scan_statistics.get_elapsed_time():.1f} seconds")
        return results
    
    def run_comprehensive_scan(self, requested_services: List[str] = None,
                             requested_accounts: List[str] = None,
                             requested_regions: List[str] = None,
                             max_workers: int = 10) -> Dict[str, Any]:
        """
        Run comprehensive scan using unified approach
        
        Args:
            requested_services: Specific services to scan
            requested_accounts: Specific accounts to scan
            requested_regions: Specific regions to scan
            max_workers: Maximum parallel workers
            
        Returns:
            Complete scan results
        """
        logger.info("🔍 Starting comprehensive compliance scan using unified approach")
        
        # Get scan targets
        targets = self.get_all_scan_targets(requested_services, requested_accounts, requested_regions)
        
        if not targets:
            logger.warning("⚠️ No scan targets generated")
            return {
                'error': 'No scan targets generated',
                'targets': [],
                'summary': {}
            }
        
        # Execute all targets
        results = self.execute_parallel_scan(targets, max_workers)
        
        # Save results
        output_path = self.save_results(results, "comprehensive_scan")
        results['output_file'] = output_path
        
        logger.info(f"💾 Results saved to: {output_path}")
        return results
    
    def get_active_accounts(self) -> List[Dict[str, Any]]:
        """Get all active accounts from organization"""
        return [acc for acc in self.discovered_accounts if acc['Status'] == 'ACTIVE']
    
    def get_enabled_accounts(self) -> Dict[str, Dict[str, Any]]:
        """Get enabled accounts with configuration"""
        active_accounts = self.get_active_accounts()
        enabled_accounts = {}
        
        for account in active_accounts:
            account_id = account['Id']
            account_config = self.config.get('account_overrides', {}).get(account_id, {})
            enabled_accounts[account_id] = {
                'account_id': account_id,
                'account_name': account_config.get('account_name', account['Name']),
                'status': account['Status'],
                'email': account['Email']
            }
        
        return enabled_accounts
    
    def get_available_services(self) -> List[str]:
        """Get available services from service discovery"""
        if self.service_discovery:
            return self.service_discovery.get_all_service_names()
        return []
    
    def save_results(self, results: Dict[str, Any], filename_prefix: str) -> str:
        """Save results to output directory"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{filename_prefix}_{timestamp}.json"
        output_path = self.output_dir / filename
        
        with open(output_path, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        return str(output_path)
    
    def display_organization_summary(self):
        """Display organization discovery summary"""
        if not self.org_structure:
            print("❌ No organization structure discovered")
            return
        
        print("\n🏢 AWS Organization Summary")
        print("=" * 50)
        print(f"Organization ID: {self.org_structure.get('organization_id', 'N/A')}")
        print(f"Master Account: {self.org_structure.get('master_account_id', 'N/A')}")
        print(f"Total Accounts: {self.org_structure.get('total_accounts', 0)}")
        print(f"Active Accounts: {self.org_structure.get('active_accounts', 0)}")
        
        # Display active accounts
        active_accounts = self.get_active_accounts()
        if active_accounts:
            print(f"\n📋 Active Accounts:")
            for account in active_accounts:
                print(f"  • {account['Name']} ({account['Id']}) - {account['Email']}")

def main():
    """Main function for testing the discovery manager"""
    print("🔍 Testing Account, Region, and Service Discovery Manager")
    print("=" * 60)
    
    try:
        # Initialize the discovery manager
        discovery_manager = AccountRegionServiceDiscoveryManager()
        
        # Display organization summary
        discovery_manager.display_organization_summary()
        
        # Get available services
        available_services = discovery_manager.get_available_services()
        print(f"\n🔧 Available Services: {len(available_services)}")
        for service in available_services:
            print(f"  • {service}")
        
        # Test scan target generation
        print(f"\n🎯 Testing Scan Target Generation...")
        targets = discovery_manager.get_all_scan_targets()
        print(f"Generated {len(targets)} scan targets")
        
        # Show first few targets
        for i, target in enumerate(targets[:5]):
            print(f"  {i+1}. {target}")
        
        if len(targets) > 5:
            print(f"  ... and {len(targets) - 5} more targets")
        
        print(f"\n✅ Discovery manager test completed successfully!")
        
    except Exception as e:
        print(f"❌ Error testing discovery manager: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main() 
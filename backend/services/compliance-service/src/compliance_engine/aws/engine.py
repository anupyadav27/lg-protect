# engine.py
"""
Unified Compliance Engine Orchestrator

Uses ScanTargets from multi_account_organization_manager for unified scanning approach.
"""

import importlib
import pkgutil
from typing import List, Dict, Any, Optional
import os
import sys
import asyncio
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import logging
import json
from pathlib import Path

# Import the simplified base classes
from base import BaseService, ComplianceResult, BaseComplianceCheck, ArnFormatter

# Import the enhanced discovery tools manager for ScanTargets
from utils.discovery_tools.account_region_service_discovery import AccountRegionServiceDiscoveryManager, ScanTarget

logger = logging.getLogger(__name__)

class ComplianceEngineOrchestrator:
    """
    Unified compliance engine that uses ScanTargets for execution
    """

    def __init__(self, config_file: str = "config/multi_account_config.json"):
        # Initialize enhanced organization manager for ScanTarget generation
        self.org_manager = AccountRegionServiceDiscoveryManager(config_file)
        
        # Initialize dynamic service discovery
        from utils.discovery_tools.service_discovery import service_discovery_manager
        self.service_discovery = service_discovery_manager
        
        # Initialize other components
        self.arn_formatter = ArnFormatter()
        
        # Output directory for results
        self.output_dir = Path("output")
        self.output_dir.mkdir(exist_ok=True)
        
        # Log discovered services
        discovered_services = self.service_discovery.get_all_service_names()
        logger.info(f"🔍 Discovered {len(discovered_services)} services: {discovered_services}")

    @property
    def checks(self) -> List[str]:
        """Get list of available service checks using dynamic discovery"""
        return self.service_discovery.get_all_service_names()

    def get_scan_targets(self, requested_services: Optional[List[str]] = None, 
                        requested_accounts: Optional[List[str]] = None,
                        requested_regions: Optional[List[str]] = None) -> List[ScanTarget]:
        """
        Get ScanTargets from multi_account_organization_manager
        
        Args:
            requested_services: Specific services to scan
            requested_accounts: Specific accounts to scan  
            requested_regions: Specific regions to scan
            
        Returns:
            List of ScanTargets to execute
        """
        logger.info("🎯 Getting scan targets from organization manager")
        # Convert None to empty lists for the multi_account_organization_manager
        services = requested_services or []
        accounts = requested_accounts or []
        regions = requested_regions or []
        targets = self.org_manager.get_all_scan_targets(services, accounts, regions)
        logger.info(f"✅ Generated {len(targets)} scan targets")
        return targets

    def execute_scan_target(self, target: ScanTarget) -> Dict[str, Any]:
        """
        Execute a single ScanTarget
        
        Args:
            target: ScanTarget to execute
            
        Returns:
            Scan results for this target
        """
        target.status = "running"
        # Use setattr to avoid type checker issues
        setattr(target, 'start_time', datetime.now())
        
        try:
            # Get account session via organization manager
            account_session = self.org_manager.session_manager.get_account_session(target.account_id)
            if not account_session:
                raise Exception(f"No session available for account {target.account_id}")
            
            # Create service instance using service discovery
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
            setattr(target, 'results', results)
            setattr(target, 'end_time', datetime.now())
            
            logger.info(f"✅ Completed scan: {target}")
            return {
                'target': target.to_dict(),
                'results': results,
                'success': True
            }
            
        except Exception as e:
            target.status = "failed"
            setattr(target, 'error', str(e))
            setattr(target, 'end_time', datetime.now())
            
            logger.error(f"❌ Failed scan: {target} - {e}")
            return {
                'target': target.to_dict(),
                'error': str(e),
                'success': False
            }

    def execute_scan_targets(self, targets: List[ScanTarget], max_workers: int = 10) -> Dict[str, Any]:
        """
        Execute multiple ScanTargets in parallel
        
        Args:
            targets: List of ScanTargets to execute
            max_workers: Maximum number of parallel workers
            
        Returns:
            Complete scan results
        """
        logger.info(f"🚀 Starting parallel execution of {len(targets)} scan targets using {max_workers} workers")
        
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
                    
                    # Log progress
                    completed = len([r for r in results['targets'] if r.get('success', False)])
                    failed = len([r for r in results['targets'] if not r.get('success', False)])
                    total = len(results['targets'])
                    logger.info(f"📊 Progress: {completed + failed}/{total} targets completed")
                    
                except Exception as e:
                    logger.error(f"❌ Unexpected error processing target {target}: {e}")
                    results['errors'].append({
                        'target': target.to_dict(),
                        'error': str(e)
                    })
        
        # Finalize results
        results['end_time'] = datetime.now().isoformat()
        results['summary'] = self._generate_scan_summary(results)
        
        logger.info(f"✅ Scan execution completed in {self._get_elapsed_time(results):.1f} seconds")
        return results

    def run_comprehensive_scan(self, requested_services: Optional[List[str]] = None,
                             requested_accounts: Optional[List[str]] = None,
                             requested_regions: Optional[List[str]] = None,
                             max_workers: int = 10) -> Dict[str, Any]:
        """
        Run comprehensive scan using unified ScanTarget approach
        
        Args:
            requested_services: Specific services to scan
            requested_accounts: Specific accounts to scan
            requested_regions: Specific regions to scan
            max_workers: Maximum parallel workers
            
        Returns:
            Complete scan results
        """
        logger.info("🔍 Starting comprehensive compliance scan using unified approach")
        
        # Get ScanTargets from organization manager
        targets = self.get_scan_targets(requested_services, requested_accounts, requested_regions)
        
        if not targets:
            logger.warning("⚠️ No scan targets generated")
            return {
                'error': 'No scan targets generated',
                'targets': [],
                'summary': {}
            }
        
        # Execute all targets
        results = self.execute_scan_targets(targets, max_workers)
        
        # Save results
        output_path = self._save_results(results, "comprehensive_scan")
        results['output_file'] = output_path
        
        logger.info(f"💾 Results saved to: {output_path}")
        return results

    def _generate_scan_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate summary statistics for scan results"""
        targets = results.get('targets', [])
        
        total_targets = len(targets)
        successful_targets = len([t for t in targets if t.get('success', False)])
        failed_targets = total_targets - successful_targets
        
        # Count findings
        total_findings = 0
        findings_by_service = {}
        findings_by_account = {}
        
        for target_result in targets:
            if target_result.get('success', False):
                target = target_result['target']
                results_list = target_result.get('results', [])
                
                # Count findings
                findings_count = len(results_list)
                total_findings += findings_count
                
                # Group by service
                service = target['service_name']
                if service not in findings_by_service:
                    findings_by_service[service] = 0
                findings_by_service[service] += findings_count
                
                # Group by account
                account = target['account_name']
                if account not in findings_by_account:
                    findings_by_account[account] = 0
                findings_by_account[account] += findings_count
        
        return {
            'total_targets': total_targets,
            'successful_targets': successful_targets,
            'failed_targets': failed_targets,
            'total_findings': total_findings,
            'findings_by_service': findings_by_service,
            'findings_by_account': findings_by_account,
            'success_rate': (successful_targets / total_targets * 100) if total_targets > 0 else 0
        }

    def _get_elapsed_time(self, results: Dict[str, Any]) -> float:
        """Get elapsed time in seconds"""
        start_time = datetime.fromisoformat(results['start_time'])
        end_time = datetime.fromisoformat(results['end_time'])
        return (end_time - start_time).total_seconds()

    def _save_results(self, results: Dict[str, Any], filename_prefix: str) -> str:
        """Save results to output directory"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{filename_prefix}_{timestamp}.json"
        output_path = self.output_dir / filename
        
        with open(output_path, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        return str(output_path)

    def display_results_summary(self, results: Dict[str, Any]):
        """Display a human-readable summary of scan results"""
        print("\n📊 Unified Compliance Scan Results")
        print("=" * 70)
        
        summary = results.get('summary', {})
        print(f"🎯 Total Targets: {summary.get('total_targets', 0)}")
        print(f"✅ Successful: {summary.get('successful_targets', 0)}")
        print(f"❌ Failed: {summary.get('failed_targets', 0)}")
        print(f"📈 Success Rate: {summary.get('success_rate', 0):.1f}%")
        print(f"🔍 Total Findings: {summary.get('total_findings', 0)}")
        
        # Service breakdown
        print(f"\n🔧 Findings by Service:")
        for service, count in summary.get('findings_by_service', {}).items():
            print(f"  📍 {service.upper()}: {count} findings")
        
        # Account breakdown
        print(f"\n🏢 Findings by Account:")
        for account, count in summary.get('findings_by_account', {}).items():
            print(f"  📍 {account}: {count} findings")
        
        print(f"\n💾 Results saved to: {results.get('output_file', 'N/A')}")
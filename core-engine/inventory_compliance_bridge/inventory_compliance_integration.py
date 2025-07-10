#!/usr/bin/env python3
"""
Inventory Compliance Integration

Main orchestrator that integrates AWS service inventory with compliance validation 
using the existing ComplianceEngine architecture. Provides flexible execution modes.
"""

import sys
import os
import json
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime
from pathlib import Path

# Add parent directories to path for imports
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.append(parent_dir)

from compliance_engine.compliance_engine import ComplianceEngine
from compliance_function_registry import ComplianceFunctionRegistry

class InventoryComplianceIntegration:
    """
    Integrates inventory discovery with compliance validation using existing ComplianceEngine.
    """
    
    def __init__(self, 
                 inventory_path: Optional[str] = None,
                 profile_name: Optional[str] = None):
        """
        Initialize integration with flexible input sources.
        
        Args:
            inventory_path: Path to inventory JSON file (optional)
            profile_name: AWS profile to use (optional)
        """
        self.logger = logging.getLogger(__name__)
        self.function_registry = ComplianceFunctionRegistry()
        self.profile_name = profile_name
        self.inventory_path = inventory_path
        
        # Default inventory path if not provided
        if not self.inventory_path:
            # Look for inventory in common locations relative to lg-protect
            lg_protect_base = "/Users/apple/Desktop/lg-protect"
            default_paths = [
                f"{lg_protect_base}/inventory/service_enablement_results/account_service_inventory.json",
                f"{lg_protect_base}/account_service_inventory.json",
                "./account_service_inventory.json"
            ]
            for path in default_paths:
                if os.path.exists(path):
                    self.inventory_path = path
                    self.logger.info(f"Found inventory at: {path}")
                    break
        
        self.logger.info(f"Initialized with inventory path: {self.inventory_path}")
    
    def load_inventory_data(self, inventory_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Load inventory data from file or use provided data.
        
        Args:
            inventory_data: Pre-loaded inventory data (optional)
            
        Returns:
            Dict containing inventory data
        """
        if inventory_data:
            self.logger.info("Using provided inventory data")
            return inventory_data
        
        if not self.inventory_path or not os.path.exists(self.inventory_path):
            # Return mock data for testing
            self.logger.warning("No inventory file found, using mock data for testing")
            return self._create_mock_inventory()
        
        try:
            with open(self.inventory_path, 'r') as f:
                data = json.load(f)
            self.logger.info(f"Successfully loaded inventory from: {self.inventory_path}")
            return data
        except Exception as e:
            self.logger.error(f"Failed to load inventory from {self.inventory_path}: {e}")
            self.logger.info("Falling back to mock inventory")
            return self._create_mock_inventory()
    
    def _create_mock_inventory(self) -> Dict[str, Any]:
        """Create mock inventory data for testing and demonstration."""
        return {
            'account_id': '123456789012',
            'account_name': 'mock-test-account',
            'discovery_timestamp': datetime.now().isoformat(),
            'discovery_method': 'mock_generation',
            'services': {
                's3': {
                    'enabled': True,
                    'regions': ['us-east-1', 'us-west-2'],
                    'identifiers': [
                        'company-prod-data-bucket',
                        'company-logs-bucket',
                        'company-backup-bucket',
                        'company-static-website'
                    ]
                },
                'ec2': {
                    'enabled': True,
                    'regions': ['us-east-1', 'us-west-2', 'eu-west-1'],
                    'identifiers': [
                        'i-1234567890abcdef0',
                        'i-0987654321fedcba0',
                        'i-abcdef1234567890',
                        'i-fedcba0987654321'
                    ]
                },
                'rds': {
                    'enabled': True,
                    'regions': ['us-east-1', 'us-west-2'],
                    'identifiers': [
                        'prod-mysql-cluster',
                        'staging-postgres-db',
                        'analytics-aurora-cluster'
                    ]
                },
                'lambda': {
                    'enabled': True,
                    'regions': ['us-east-1', 'us-west-2', 'eu-west-1'],
                    'identifiers': [
                        'api-gateway-handler',
                        'data-processing-function',
                        'notification-service',
                        'auth-validator'
                    ]
                },
                'iam': {
                    'enabled': True,
                    'regions': ['global'],
                    'identifiers': [
                        'account-wide-policies',
                        'user-management',
                        'role-management'
                    ]
                }
            }
        }
    
    def run_inventory_compliance_validation(self, 
                                          inventory_data: Optional[Dict[str, Any]] = None,
                                          services_filter: Optional[List[str]] = None,
                                          functions_filter: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Run complete compliance validation based on inventory.
        
        Args:
            inventory_data: Pre-loaded inventory (optional)
            services_filter: Only run compliance for these services (optional)
            functions_filter: Only run these specific functions (optional)
            
        Returns:
            Complete compliance validation results
        """
        print("🚀 STARTING INVENTORY-BASED COMPLIANCE VALIDATION")
        print("=" * 70)
        
        # Load inventory data
        inventory = self.load_inventory_data(inventory_data)
        
        # Initialize comprehensive results structure
        integration_results = {
            'metadata': {
                'account_id': inventory.get('account_id'),
                'account_name': inventory.get('account_name'),
                'inventory_timestamp': inventory.get('discovery_timestamp'),
                'compliance_timestamp': datetime.now().isoformat(),
                'profile_used': self.profile_name or 'default',
                'inventory_source': self.inventory_path or 'provided_data',
                'discovery_method': inventory.get('discovery_method', 'unknown')
            },
            'execution_summary': {
                'total_services_found': 0,
                'services_with_compliance': 0,
                'total_functions_executed': 0,
                'total_resources_checked': 0,
                'overall_compliance_score': 0.0,
                'execution_start_time': datetime.now().isoformat()
            },
            'service_results': {},
            'all_findings': [],
            'execution_errors': [],
            'registry_stats': self.function_registry.get_registry_stats(),
            'filters_applied': {
                'services_filter': services_filter,
                'functions_filter': functions_filter
            }
        }
        
        services = inventory.get('services', {})
        integration_results['execution_summary']['total_services_found'] = len(services)
        
        print(f"📊 INVENTORY ANALYSIS:")
        print(f"   Account: {inventory.get('account_name')} ({inventory.get('account_id')})")
        print(f"   Services Found: {len(services)}")
        print(f"   AWS Profile: {self.profile_name or 'default'}")
        print(f"   Inventory Source: {self.inventory_path or 'provided data'}")
        
        # Process each service from inventory
        for service_name, service_data in services.items():
            if not service_data.get('enabled', False):
                print(f"   ⏭️  Skipping {service_name} (not enabled)")
                continue
            
            if services_filter and service_name not in services_filter:
                print(f"   ⏭️  Skipping {service_name} (filtered out)")
                continue
            
            identifiers = service_data.get('identifiers', [])
            if not identifiers:
                print(f"   ⚠️  {service_name} has no resource identifiers")
                continue
            
            print(f"\n🔧 Processing {service_name.upper()} Service:")
            print(f"   Resources Found: {len(identifiers)}")
            print(f"   Regions: {', '.join(service_data.get('regions', ['unknown']))}")
            
            integration_results['execution_summary']['total_resources_checked'] += len(identifiers)
            
            # Get compliance functions for this service
            available_functions = self.function_registry.get_functions_by_service(service_name)
            
            if functions_filter:
                available_functions = [f for f in available_functions if f in functions_filter]
            
            if not available_functions:
                print(f"   ⚠️  No compliance functions available for {service_name}")
                continue
            
            print(f"   Compliance Functions: {len(available_functions)}")
            for func in available_functions:
                metadata = self.function_registry.get_function_metadata(func)
                print(f"     • {func} ({metadata.get('severity', 'UNKNOWN')})")
            
            integration_results['execution_summary']['services_with_compliance'] += 1
            
            # Initialize service results
            service_results = {
                'service_name': service_name,
                'resource_count': len(identifiers),
                'resource_identifiers': identifiers,
                'regions': service_data.get('regions', []),
                'function_executions': [],
                'total_findings': 0,
                'compliance_score': 0.0,
                'errors': [],
                'execution_start_time': datetime.now().isoformat()
            }
            
            # Execute each compliance function for this service
            for function_name in available_functions:
                print(f"   ⚡ Executing: {function_name}")
                
                try:
                    # Execute compliance function using existing ComplianceEngine
                    function_results = self._execute_compliance_function(
                        function_name, service_name, identifiers, service_data.get('regions', [])
                    )
                    
                    service_results['function_executions'].append({
                        'function_name': function_name,
                        'results': function_results,
                        'findings_count': len(function_results.get('findings', [])),
                        'errors_count': len(function_results.get('errors', [])),
                        'execution_time': function_results.get('timestamp'),
                        'status': function_results.get('status', 'UNKNOWN')
                    })
                    
                    # Add findings to overall results
                    findings = function_results.get('findings', [])
                    service_results['total_findings'] += len(findings)
                    integration_results['all_findings'].extend(findings)
                    integration_results['execution_summary']['total_functions_executed'] += 1
                    
                    # Add errors if any
                    errors = function_results.get('errors', [])
                    if errors:
                        service_results['errors'].extend(errors)
                        integration_results['execution_errors'].extend(errors)
                    
                    print(f"     ✅ Completed: {len(findings)} findings, {len(errors)} errors")
                    
                except Exception as e:
                    error_msg = f"Failed to execute {function_name}: {str(e)}"
                    print(f"     ❌ Error: {error_msg}")
                    service_results['errors'].append({
                        'function_name': function_name,
                        'error_message': error_msg,
                        'timestamp': datetime.now().isoformat()
                    })
                    integration_results['execution_errors'].append({
                        'service': service_name,
                        'function': function_name,
                        'error': error_msg,
                        'timestamp': datetime.now().isoformat()
                    })
            
            # Calculate service compliance score
            total_findings = service_results['total_findings']
            if total_findings > 0:
                compliant_findings = sum(
                    1 for exec_result in service_results['function_executions']
                    for finding in exec_result['results'].get('findings', [])
                    if finding.get('compliance_status') == 'COMPLIANT'
                )
                service_results['compliance_score'] = (compliant_findings / total_findings) * 100
            
            service_results['execution_end_time'] = datetime.now().isoformat()
            integration_results['service_results'][service_name] = service_results
            
            print(f"   📊 {service_name} Summary: {service_results['total_findings']} findings, "
                  f"{service_results['compliance_score']:.1f}% compliant")
        
        # Calculate overall compliance score
        total_findings = len(integration_results['all_findings'])
        if total_findings > 0:
            compliant_findings = len([
                f for f in integration_results['all_findings']
                if f.get('compliance_status') == 'COMPLIANT'
            ])
            integration_results['execution_summary']['overall_compliance_score'] = (
                compliant_findings / total_findings
            ) * 100
        
        integration_results['execution_summary']['execution_end_time'] = datetime.now().isoformat()
        
        # Print final summary
        self._print_final_summary(integration_results)
        
        return integration_results
    
    def _execute_compliance_function(self, 
                                   function_name: str, 
                                   service_name: str, 
                                   identifiers: List[str],
                                   regions: List[str]) -> Dict[str, Any]:
        """
        Execute a single compliance function using the existing ComplianceEngine.
        
        Args:
            function_name: Name of compliance function to execute
            service_name: AWS service name
            identifiers: List of resource identifiers
            regions: List of regions for the service
            
        Returns:
            Results from compliance function execution
        """
        try:
            # Create compliance data structure for existing engine
            compliance_data = {
                'compliance_name': f"{service_name}_{function_name}",
                'function_name': function_name,
                'api_function': f"boto3.client('{service_name}')",
                'service': service_name
            }
            
            # Initialize compliance engine with existing architecture
            engine = ComplianceEngine(compliance_data)
            
            # Create resource-specific compliance function
            compliance_check_function = self.function_registry.create_compliance_engine_function(
                function_name, identifiers
            )
            
            # Execute using existing ComplianceEngine
            results = engine.run_compliance_check(
                compliance_check_function,
                profile_name=self.profile_name
            )
            
            # Enhance results with bridge metadata
            results['bridge_metadata'] = {
                'function_name': function_name,
                'service_name': service_name,
                'resource_identifiers': identifiers,
                'resource_count': len(identifiers),
                'regions_processed': regions
            }
            
            return results
            
        except Exception as e:
            self.logger.error(f"Failed to execute compliance function {function_name}: {e}")
            return {
                'compliance_name': f"{service_name}_{function_name}",
                'function_name': function_name,
                'status': 'ERROR',
                'findings': [],
                'errors': [{
                    'error_type': 'ExecutionError',
                    'error_message': str(e),
                    'timestamp': datetime.now().isoformat()
                }],
                'timestamp': datetime.now().isoformat()
            }
    
    def _print_final_summary(self, results: Dict[str, Any]):
        """Print comprehensive final execution summary."""
        summary = results['execution_summary']
        metadata = results['metadata']
        
        print(f"\n{'='*70}")
        print("📊 INVENTORY COMPLIANCE VALIDATION COMPLETED")
        print(f"{'='*70}")
        print(f"Account: {metadata['account_name']} ({metadata['account_id']})")
        print(f"Execution Profile: {metadata['profile_used']}")
        print(f"Services Found: {summary['total_services_found']}")
        print(f"Services with Compliance: {summary['services_with_compliance']}")
        print(f"Functions Executed: {summary['total_functions_executed']}")
        print(f"Resources Checked: {summary['total_resources_checked']}")
        print(f"Total Findings: {len(results['all_findings'])}")
        print(f"Overall Compliance Score: {summary['overall_compliance_score']:.1f}%")
        
        # Service breakdown
        if results['service_results']:
            print(f"\n📋 SERVICE BREAKDOWN:")
            for service, service_result in results['service_results'].items():
                print(f"   {service.upper()}: {service_result['total_findings']} findings "
                      f"({service_result['compliance_score']:.1f}% compliant)")
        
        # Error summary
        if results['execution_errors']:
            print(f"\n⚠️  EXECUTION ERRORS: {len(results['execution_errors'])}")
            error_summary = {}
            for error in results['execution_errors']:
                service = error.get('service', 'unknown')
                error_summary[service] = error_summary.get(service, 0) + 1
            
            for service, count in error_summary.items():
                print(f"   {service}: {count} errors")
        
        # Compliance status
        score = summary['overall_compliance_score']
        if score >= 90:
            print(f"\n🎉 EXCELLENT: High compliance score!")
        elif score >= 70:
            print(f"\n✅ GOOD: Reasonable compliance, some improvements needed")
        elif score >= 50:
            print(f"\n⚠️  MODERATE: Multiple compliance issues need attention")
        else:
            print(f"\n🚨 CRITICAL: Significant compliance issues require immediate action")
    
    def save_results(self, results: Dict[str, Any], output_path: Optional[str] = None) -> Optional[str]:
        """Save compliance results to file."""
        if not output_path:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            account_id = results.get('metadata', {}).get('account_id', 'unknown')
            output_path = f"/Users/apple/Desktop/lg-protect/core-engine/inventory_compliance_bridge/results/compliance_results_{account_id}_{timestamp}.json"
        
        # Ensure results directory exists
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        try:
            with open(output_path, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            print(f"\n💾 Results saved to: {output_path}")
            self.logger.info(f"Results saved to: {output_path}")
            return output_path
        except Exception as e:
            error_msg = f"Failed to save results to {output_path}: {e}"
            print(f"\n❌ {error_msg}")
            self.logger.error(error_msg)
            return None

# Convenience Functions for Different Use Cases

def run_from_inventory_file(inventory_path: str, 
                           profile_name: Optional[str] = None,
                           services_filter: Optional[List[str]] = None) -> Dict[str, Any]:
    """
    Run compliance validation from inventory file.
    
    Args:
        inventory_path: Path to inventory JSON file
        profile_name: AWS profile to use
        services_filter: Only check these services
        
    Returns:
        Compliance validation results
    """
    integration = InventoryComplianceIntegration(inventory_path, profile_name)
    return integration.run_inventory_compliance_validation(services_filter=services_filter)

def run_from_inventory_data(inventory_data: Dict[str, Any],
                           profile_name: Optional[str] = None) -> Dict[str, Any]:
    """
    Run compliance validation from inventory data.
    
    Args:
        inventory_data: Inventory data dictionary
        profile_name: AWS profile to use
        
    Returns:
        Compliance validation results
    """
    integration = InventoryComplianceIntegration(profile_name=profile_name)
    return integration.run_inventory_compliance_validation(inventory_data)

def run_with_defaults() -> Dict[str, Any]:
    """
    Run compliance validation with default settings.
    Looks for inventory in default locations.
    
    Returns:
        Compliance validation results
    """
    integration = InventoryComplianceIntegration()
    return integration.run_inventory_compliance_validation()

# Quick test function
def quick_test_integration() -> bool:
    """Run a quick test of the integration."""
    print("🧪 QUICK INTEGRATION TEST")
    print("-" * 30)
    
    try:
        integration = InventoryComplianceIntegration()
        results = integration.run_inventory_compliance_validation()
        
        # Basic validation
        required_keys = ['metadata', 'execution_summary', 'service_results']
        success = all(key in results for key in required_keys)
        
        if success:
            print("✅ Quick test PASSED")
            return True
        else:
            print("❌ Quick test FAILED - Missing required keys")
            return False
            
    except Exception as e:
        print(f"❌ Quick test FAILED - Exception: {e}")
        return False
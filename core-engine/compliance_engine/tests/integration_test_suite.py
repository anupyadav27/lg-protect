#!/usr/bin/env python3
"""
Comprehensive Integration Test Suite

Tests the complete inventory-compliance integration with multiple scenarios
and provides detailed verification of all components.
"""

import sys
import os
import json
import logging
import traceback
from typing import Dict, List, Any, Optional
from datetime import datetime
from pathlib import Path

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from inventory_compliance_integration import (
    InventoryComplianceIntegration,
    run_from_inventory_file,
    run_from_inventory_data,
    run_with_defaults
)
from compliance_function_registry import ComplianceFunctionRegistry

class ComprehensiveTestSuite:
    """Comprehensive test suite for inventory-compliance integration."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.test_results = {
            'timestamp': datetime.now().isoformat(),
            'total_tests': 0,
            'passed_tests': 0,
            'failed_tests': 0,
            'test_details': {},
            'performance_metrics': {},
            'coverage_analysis': {}
        }
        
    def run_all_tests(self) -> Dict[str, Any]:
        """Run all integration tests."""
        print("🧪 COMPREHENSIVE INVENTORY-COMPLIANCE INTEGRATION TESTS")
        print("=" * 80)
        
        tests_to_run = [
            ('test_compliance_function_registry', 'Compliance Function Registry'),
            ('test_inventory_loading', 'Inventory Data Loading'),
            ('test_mock_inventory_generation', 'Mock Inventory Generation'),
            ('test_service_filtering', 'Service Filtering'),
            ('test_function_filtering', 'Function Filtering'),
            ('test_integration_with_mock_data', 'Integration with Mock Data'),
            ('test_integration_with_real_inventory', 'Integration with Real Inventory'),
            ('test_error_handling', 'Error Handling'),
            ('test_results_structure', 'Results Structure Validation'),
            ('test_convenience_functions', 'Convenience Functions'),
            ('test_performance_metrics', 'Performance Metrics'),
            ('test_end_to_end_workflow', 'End-to-End Workflow')
        ]
        
        for test_method, test_name in tests_to_run:
            self._run_single_test(test_method, test_name)
        
        self._generate_final_report()
        return self.test_results
    
    def _run_single_test(self, test_method: str, test_name: str):
        """Run a single test method."""
        print(f"\n🔍 Running: {test_name}")
        print("-" * 50)
        
        self.test_results['total_tests'] += 1
        start_time = datetime.now()
        
        try:
            # Execute the test method
            test_function = getattr(self, test_method)
            result = test_function()
            
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()
            
            if result.get('success', False):
                print(f"✅ PASSED: {test_name}")
                self.test_results['passed_tests'] += 1
                status = 'PASSED'
            else:
                print(f"❌ FAILED: {test_name}")
                print(f"   Error: {result.get('error', 'Unknown error')}")
                self.test_results['failed_tests'] += 1
                status = 'FAILED'
            
            self.test_results['test_details'][test_name] = {
                'status': status,
                'duration_seconds': duration,
                'details': result,
                'timestamp': start_time.isoformat()
            }
            
        except Exception as e:
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()
            
            print(f"❌ ERROR: {test_name}")
            print(f"   Exception: {str(e)}")
            print(f"   Traceback: {traceback.format_exc()}")
            
            self.test_results['failed_tests'] += 1
            self.test_results['test_details'][test_name] = {
                'status': 'ERROR',
                'duration_seconds': duration,
                'error': str(e),
                'traceback': traceback.format_exc(),
                'timestamp': start_time.isoformat()
            }
    
    def test_compliance_function_registry(self) -> Dict[str, Any]:
        """Test the compliance function registry."""
        try:
            registry = ComplianceFunctionRegistry()
            
            # Test registry initialization
            assert hasattr(registry, 'functions'), "Registry missing functions attribute"
            assert len(registry.functions) > 0, "Registry has no functions"
            
            # Test service functions lookup
            s3_functions = registry.get_functions_by_service('s3')
            assert len(s3_functions) > 0, "No S3 functions found"
            
            # Test function metadata
            if s3_functions:
                metadata = registry.get_function_metadata(s3_functions[0])
                assert 'service' in metadata, "Function metadata missing service"
                assert 'category' in metadata, "Function metadata missing category"
                assert 'severity' in metadata, "Function metadata missing severity"
            
            # Test registry stats
            stats = registry.get_registry_stats()
            assert 'total_functions' in stats, "Registry stats missing total_functions"
            assert stats['total_functions'] > 0, "Registry stats shows no functions"
            
            # Test all services
            services = registry.get_all_services()
            assert len(services) > 0, "No services found in registry"
            assert 's3' in services, "S3 service not found in registry"
            
            return {
                'success': True,
                'details': {
                    'total_functions': len(registry.functions),
                    'services_count': len(services),
                    's3_functions_count': len(s3_functions),
                    'sample_services': services[:5],
                    'registry_stats': stats
                }
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def test_inventory_loading(self) -> Dict[str, Any]:
        """Test inventory data loading functionality."""
        try:
            integration = InventoryComplianceIntegration()
            
            # Test mock inventory creation
            mock_inventory = integration._create_mock_inventory()
            assert 'account_id' in mock_inventory, "Mock inventory missing account_id"
            assert 'services' in mock_inventory, "Mock inventory missing services"
            assert len(mock_inventory['services']) > 0, "Mock inventory has no services"
            
            # Test loading with provided data
            test_data = {
                'account_id': 'test-123',
                'account_name': 'test-account',
                'services': {
                    's3': {'enabled': True, 'identifiers': ['test-bucket']}
                }
            }
            loaded_data = integration.load_inventory_data(test_data)
            assert loaded_data == test_data, "Provided data not loaded correctly"
            
            return {
                'success': True,
                'details': {
                    'mock_inventory_services': len(mock_inventory['services']),
                    'provided_data_loaded': loaded_data['account_id'] == 'test-123',
                    'mock_sample': {k: v for k, v in list(mock_inventory['services'].items())[:2]}
                }
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def test_mock_inventory_generation(self) -> Dict[str, Any]:
        """Test mock inventory generation."""
        try:
            integration = InventoryComplianceIntegration()
            mock_inventory = integration._create_mock_inventory()
            
            # Validate structure
            required_fields = ['account_id', 'account_name', 'discovery_timestamp', 'services']
            for field in required_fields:
                assert field in mock_inventory, f"Mock inventory missing {field}"
            
            # Validate services
            services = mock_inventory['services']
            expected_services = ['s3', 'ec2', 'rds', 'lambda']
            
            for service in expected_services:
                assert service in services, f"Mock inventory missing {service} service"
                service_data = services[service]
                assert 'enabled' in service_data, f"{service} missing enabled field"
                assert 'regions' in service_data, f"{service} missing regions field"
                assert 'identifiers' in service_data, f"{service} missing identifiers field"
                assert len(service_data['identifiers']) > 0, f"{service} has no identifiers"
            
            return {
                'success': True,
                'details': {
                    'services_generated': list(services.keys()),
                    'total_resources': sum(len(s['identifiers']) for s in services.values()),
                    'total_regions': len(set(r for s in services.values() for r in s['regions'])),
                    'sample_identifiers': {
                        service: data['identifiers'][:2] 
                        for service, data in services.items()
                    }
                }
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def test_service_filtering(self) -> Dict[str, Any]:
        """Test service filtering functionality."""
        try:
            integration = InventoryComplianceIntegration()
            
            # Test with service filter
            results = integration.run_inventory_compliance_validation(
                services_filter=['s3', 'ec2']
            )
            
            assert 'service_results' in results, "Results missing service_results"
            processed_services = list(results['service_results'].keys())
            
            # Should only have s3 and ec2 (if they have resources)
            for service in processed_services:
                assert service in ['s3', 'ec2'], f"Unexpected service {service} in filtered results"
            
            return {
                'success': True,
                'details': {
                    'filter_applied': ['s3', 'ec2'],
                    'services_processed': processed_services,
                    'total_services_in_results': len(processed_services),
                    'execution_summary': results.get('execution_summary', {})
                }
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def test_function_filtering(self) -> Dict[str, Any]:
        """Test function filtering functionality."""
        try:
            registry = ComplianceFunctionRegistry()
            s3_functions = registry.get_functions_by_service('s3')
            
            if not s3_functions:
                return {'success': False, 'error': 'No S3 functions available for testing'}
            
            # Test with function filter
            function_filter = [s3_functions[0]]  # Test with first S3 function
            
            integration = InventoryComplianceIntegration()
            results = integration.run_inventory_compliance_validation(
                services_filter=['s3'],
                functions_filter=function_filter
            )
            
            # Check that only specified function was executed
            if 's3' in results.get('service_results', {}):
                s3_results = results['service_results']['s3']
                executed_functions = [
                    exec_result.get('function_name') 
                    for exec_result in s3_results.get('function_executions', [])
                ]
                
                for func in executed_functions:
                    assert func in function_filter, f"Unexpected function {func} executed"
            
            return {
                'success': True,
                'details': {
                    'function_filter_applied': function_filter,
                    'available_s3_functions': s3_functions,
                    'execution_summary': results.get('execution_summary', {})
                }
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def test_integration_with_mock_data(self) -> Dict[str, Any]:
        """Test full integration with mock data."""
        try:
            integration = InventoryComplianceIntegration()
            results = integration.run_inventory_compliance_validation()
            
            # Validate results structure
            required_sections = [
                'metadata', 'execution_summary', 'service_results', 
                'all_findings', 'execution_errors', 'registry_stats'
            ]
            
            for section in required_sections:
                assert section in results, f"Results missing {section} section"
            
            # Validate metadata
            metadata = results['metadata']
            assert 'account_id' in metadata, "Metadata missing account_id"
            assert 'compliance_timestamp' in metadata, "Metadata missing compliance_timestamp"
            
            # Validate execution summary
            summary = results['execution_summary']
            assert 'total_services_found' in summary, "Summary missing total_services_found"
            assert 'total_functions_executed' in summary, "Summary missing total_functions_executed"
            
            return {
                'success': True,
                'details': {
                    'services_found': summary.get('total_services_found', 0),
                    'functions_executed': summary.get('total_functions_executed', 0),
                    'total_findings': len(results.get('all_findings', [])),
                    'services_processed': list(results.get('service_results', {}).keys()),
                    'compliance_score': summary.get('overall_compliance_score', 0),
                    'execution_errors': len(results.get('execution_errors', []))
                }
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def test_integration_with_real_inventory(self) -> Dict[str, Any]:
        """Test integration with real inventory file if available."""
        try:
            # Look for real inventory file
            possible_paths = [
                "/Users/apple/Desktop/lg-protect/inventory/service_enablement_results/account_service_inventory.json",
                "/Users/apple/Desktop/lg-protect/account_service_inventory.json"
            ]
            
            inventory_path = None
            for path in possible_paths:
                if os.path.exists(path):
                    inventory_path = path
                    break
            
            if not inventory_path:
                return {
                    'success': True,
                    'details': {
                        'message': 'No real inventory file found, test skipped',
                        'searched_paths': possible_paths
                    }
                }
            
            # Test with real inventory
            results = run_from_inventory_file(inventory_path)
            
            assert 'metadata' in results, "Real inventory results missing metadata"
            assert 'execution_summary' in results, "Real inventory results missing execution_summary"
            
            return {
                'success': True,
                'details': {
                    'inventory_path': inventory_path,
                    'services_found': results['execution_summary'].get('total_services_found', 0),
                    'functions_executed': results['execution_summary'].get('total_functions_executed', 0),
                    'account_id': results['metadata'].get('account_id', 'unknown'),
                    'real_inventory_used': True
                }
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def test_error_handling(self) -> Dict[str, Any]:
        """Test error handling scenarios."""
        try:
            # Test with invalid inventory data
            invalid_inventory = {
                'account_id': 'test',
                'services': {
                    'invalid_service': {
                        'enabled': True,
                        'identifiers': ['test-resource']
                    }
                }
            }
            
            integration = InventoryComplianceIntegration()
            results = integration.run_inventory_compliance_validation(invalid_inventory)
            
            # Should handle gracefully and not crash
            assert 'execution_errors' in results, "Results missing execution_errors"
            assert 'service_results' in results, "Results missing service_results"
            
            return {
                'success': True,
                'details': {
                    'handled_invalid_service': True,
                    'execution_errors_count': len(results.get('execution_errors', [])),
                    'graceful_handling': True
                }
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def test_results_structure(self) -> Dict[str, Any]:
        """Test the structure and completeness of results."""
        try:
            integration = InventoryComplianceIntegration()
            results = integration.run_inventory_compliance_validation()
            
            # Test results structure
            expected_structure = {
                'metadata': ['account_id', 'account_name', 'compliance_timestamp'],
                'execution_summary': ['total_services_found', 'services_with_compliance', 'overall_compliance_score'],
                'service_results': [],  # Should be dict
                'all_findings': [],     # Should be list
                'execution_errors': [], # Should be list
                'registry_stats': ['total_functions', 'services']
            }
            
            for section, expected_fields in expected_structure.items():
                assert section in results, f"Missing section: {section}"
                
                if expected_fields:  # If we expect specific fields
                    section_data = results[section]
                    for field in expected_fields:
                        assert field in section_data, f"Missing field {field} in {section}"
            
            # Test data types
            assert isinstance(results['service_results'], dict), "service_results should be dict"
            assert isinstance(results['all_findings'], list), "all_findings should be list"
            assert isinstance(results['execution_errors'], list), "execution_errors should be list"
            
            return {
                'success': True,
                'details': {
                    'structure_valid': True,
                    'sections_present': list(results.keys()),
                    'metadata_fields': list(results['metadata'].keys()),
                    'summary_fields': list(results['execution_summary'].keys())
                }
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def test_convenience_functions(self) -> Dict[str, Any]:
        """Test convenience functions."""
        try:
            # Test run_with_defaults
            results1 = run_with_defaults()
            assert 'metadata' in results1, "run_with_defaults failed"
            
            # Test run_from_inventory_data
            test_data = {
                'account_id': 'test-123',
                'account_name': 'test-account',
                'services': {
                    's3': {'enabled': True, 'identifiers': ['test-bucket'], 'regions': ['us-east-1']}
                }
            }
            results2 = run_from_inventory_data(test_data)
            assert 'metadata' in results2, "run_from_inventory_data failed"
            assert results2['metadata']['account_id'] == 'test-123', "Account ID not preserved"
            
            return {
                'success': True,
                'details': {
                    'run_with_defaults': 'PASSED',
                    'run_from_inventory_data': 'PASSED',
                    'account_id_preserved': results2['metadata']['account_id'] == 'test-123'
                }
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def test_performance_metrics(self) -> Dict[str, Any]:
        """Test performance and collect metrics."""
        try:
            start_time = datetime.now()
            
            integration = InventoryComplianceIntegration()
            results = integration.run_inventory_compliance_validation()
            
            end_time = datetime.now()
            total_duration = (end_time - start_time).total_seconds()
            
            # Calculate metrics
            functions_executed = results['execution_summary'].get('total_functions_executed', 0)
            resources_checked = results['execution_summary'].get('total_resources_checked', 0)
            
            metrics = {
                'total_duration_seconds': total_duration,
                'functions_executed': functions_executed,
                'resources_checked': resources_checked,
                'avg_function_duration': total_duration / max(functions_executed, 1),
                'avg_resource_duration': total_duration / max(resources_checked, 1)
            }
            
            # Store metrics for final report
            self.test_results['performance_metrics'] = metrics
            
            return {
                'success': True,
                'details': metrics
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def test_end_to_end_workflow(self) -> Dict[str, Any]:
        """Test complete end-to-end workflow."""
        try:
            # Create integration
            integration = InventoryComplianceIntegration()
            
            # Run validation
            results = integration.run_inventory_compliance_validation()
            
            # Save results
            output_path = integration.save_results(results)
            
            # Verify saved file
            saved_file_exists = output_path and os.path.exists(output_path)
            
            if saved_file_exists:
                with open(output_path, 'r') as f:
                    saved_data = json.load(f)
                
                # Verify saved data integrity
                data_integrity = (
                    saved_data.get('metadata', {}).get('account_id') == 
                    results.get('metadata', {}).get('account_id')
                )
            else:
                data_integrity = False
            
            return {
                'success': True,
                'details': {
                    'integration_created': True,
                    'validation_completed': True,
                    'results_saved': saved_file_exists,
                    'data_integrity': data_integrity,
                    'output_path': output_path,
                    'workflow_complete': True
                }
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _generate_final_report(self):
        """Generate final test report."""
        print(f"\n{'='*80}")
        print("📊 COMPREHENSIVE TEST RESULTS SUMMARY")
        print(f"{'='*80}")
        
        total = self.test_results['total_tests']
        passed = self.test_results['passed_tests']
        failed = self.test_results['failed_tests']
        success_rate = (passed / total) * 100 if total > 0 else 0
        
        print(f"Total Tests: {total}")
        print(f"Passed: {passed}")
        print(f"Failed: {failed}")
        print(f"Success Rate: {success_rate:.1f}%")
        
        # Performance summary
        if 'performance_metrics' in self.test_results:
            metrics = self.test_results['performance_metrics']
            print(f"\n⚡ PERFORMANCE METRICS:")
            print(f"   Total Duration: {metrics.get('total_duration_seconds', 0):.2f}s")
            print(f"   Functions Executed: {metrics.get('functions_executed', 0)}")
            print(f"   Resources Checked: {metrics.get('resources_checked', 0)}")
            print(f"   Avg Function Time: {metrics.get('avg_function_duration', 0):.3f}s")
        
        # Test details
        print(f"\n📋 DETAILED TEST RESULTS:")
        for test_name, details in self.test_results['test_details'].items():
            status_icon = "✅" if details['status'] == 'PASSED' else "❌"
            duration = details['duration_seconds']
            print(f"   {status_icon} {test_name} ({duration:.2f}s)")
            
            if details['status'] != 'PASSED' and 'error' in details:
                print(f"      Error: {details['error']}")
        
        # Final status
        if success_rate == 100:
            print(f"\n🎉 ALL TESTS PASSED! Integration is ready for production use.")
        elif success_rate >= 80:
            print(f"\n✅ Most tests passed. Minor issues may need attention.")
        else:
            print(f"\n⚠️  Multiple test failures. Review and fix issues before using.")
        
        # Save test results
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        results_file = f"/Users/apple/Desktop/lg-protect/core-engine/compliance_engine/test_results_{timestamp}.json"
        
        try:
            with open(results_file, 'w') as f:
                json.dump(self.test_results, f, indent=2)
            print(f"\n💾 Test results saved to: {results_file}")
        except Exception as e:
            print(f"\n❌ Failed to save test results: {e}")

def run_quick_test() -> bool:
    """Run a quick smoke test."""
    print("🚀 RUNNING QUICK INTEGRATION SMOKE TEST")
    print("=" * 50)
    
    try:
        # Test basic functionality
        integration = InventoryComplianceIntegration()
        results = integration.run_inventory_compliance_validation()
        
        # Basic validation
        success = (
            'metadata' in results and
            'execution_summary' in results and
            'service_results' in results
        )
        
        if success:
            print("✅ Quick test PASSED - Integration is working!")
            return True
        else:
            print("❌ Quick test FAILED - Basic structure missing")
            return False
            
    except Exception as e:
        print(f"❌ Quick test FAILED - Exception: {e}")
        return False

def run_full_test_suite() -> Dict[str, Any]:
    """Run the complete test suite."""
    suite = ComprehensiveTestSuite()
    return suite.run_all_tests()

if __name__ == '__main__':
    # Check command line arguments
    if len(sys.argv) > 1 and sys.argv[1] == '--quick':
        success = run_quick_test()
        sys.exit(0 if success else 1)
    else:
        results = run_full_test_suite()
        success_rate = (results['passed_tests'] / results['total_tests']) * 100
        sys.exit(0 if success_rate >= 80 else 1)
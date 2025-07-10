#!/usr/bin/env python3
"""
Main Integration Runner

Provides flexible entry points for running inventory-based compliance validation.
Supports multiple execution modes and easy command-line usage.
"""

import sys
import os
import argparse
import json
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime
from pathlib import Path

# Add current directory to path for imports
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(current_dir)

from inventory_compliance_integration import (
    InventoryComplianceIntegration,
    run_from_inventory_file,
    run_from_inventory_data,
    run_with_defaults,
    quick_test_integration
)
from compliance_function_registry import ComplianceFunctionRegistry

def setup_logging(verbose: bool = False):
    """Setup logging configuration."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

def print_banner():
    """Print application banner."""
    print("🛡️  INVENTORY-COMPLIANCE INTEGRATION RUNNER")
    print("=" * 60)
    print("Integrates AWS service inventory with compliance validation")
    print("Uses your existing ComplianceEngine architecture")
    print("=" * 60)

def list_available_functions():
    """List all available compliance functions."""
    print("📋 AVAILABLE COMPLIANCE FUNCTIONS:")
    print("-" * 40)
    
    registry = ComplianceFunctionRegistry()
    stats = registry.get_registry_stats()
    
    print(f"Total Functions: {stats['total_functions']}")
    print(f"Services Covered: {len(stats['services'])}")
    
    print("\n🔧 Functions by Service:")
    for service in registry.get_all_services():
        functions = registry.get_functions_by_service(service)
        print(f"\n  📦 {service.upper()} ({len(functions)} functions):")
        for func in functions:
            metadata = registry.get_function_metadata(func)
            severity = metadata.get('severity', 'UNKNOWN')
            category = metadata.get('category', 'unknown')
            print(f"    • {func} [{severity}] ({category})")

def run_mode_default(args) -> Dict[str, Any]:
    """Run with default settings - auto-detect inventory."""
    print("🚀 RUNNING DEFAULT MODE")
    print("Looking for inventory in default locations...")
    
    integration = InventoryComplianceIntegration(profile_name=args.profile)
    
    # Apply filters if provided
    services_filter = args.services.split(',') if args.services else None
    functions_filter = args.functions.split(',') if args.functions else None
    
    results = integration.run_inventory_compliance_validation(
        services_filter=services_filter,
        functions_filter=functions_filter
    )
    
    if args.save:
        integration.save_results(results, args.output)
    
    return results

def run_mode_file(args) -> Dict[str, Any]:
    """Run with specified inventory file."""
    print(f"🚀 RUNNING FILE MODE")
    print(f"Loading inventory from: {args.file}")
    
    if not os.path.exists(args.file):
        print(f"❌ Error: Inventory file not found: {args.file}")
        sys.exit(1)
    
    services_filter = args.services.split(',') if args.services else None
    
    results = run_from_inventory_file(
        args.file, 
        profile_name=args.profile,
        services_filter=services_filter
    )
    
    if args.save:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_path = args.output or f"compliance_results_{timestamp}.json"
        with open(output_path, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        print(f"💾 Results saved to: {output_path}")
    
    return results

def run_mode_interactive(args) -> Dict[str, Any]:
    """Run in interactive mode with user prompts."""
    print("🚀 RUNNING INTERACTIVE MODE")
    print("=" * 30)
    
    # Get inventory source
    print("\n📂 INVENTORY SOURCE:")
    print("1. Use default locations (auto-detect)")
    print("2. Specify file path")
    print("3. Use mock data for testing")
    
    choice = input("\nSelect option (1-3): ").strip()
    
    inventory_data = None
    inventory_path = None
    
    if choice == "1":
        print("Using default inventory locations...")
    elif choice == "2":
        inventory_path = input("Enter inventory file path: ").strip()
        if not os.path.exists(inventory_path):
            print(f"❌ File not found: {inventory_path}")
            sys.exit(1)
    elif choice == "3":
        print("Using mock data for testing...")
        integration_temp = InventoryComplianceIntegration()
        inventory_data = integration_temp._create_mock_inventory()
    else:
        print("Invalid choice. Using default.")
    
    # Get service filter
    print("\n🔧 SERVICE FILTER (optional):")
    registry = ComplianceFunctionRegistry()
    available_services = registry.get_all_services()
    print(f"Available services: {', '.join(available_services)}")
    
    services_input = input("Enter services to check (comma-separated, or press Enter for all): ").strip()
    services_filter = services_input.split(',') if services_input else None
    
    # Get profile
    profile_input = input(f"\nAWS Profile (current: {args.profile or 'default'}): ").strip()
    profile = profile_input if profile_input else args.profile
    
    # Run integration
    print(f"\n⚡ STARTING COMPLIANCE VALIDATION...")
    
    integration = InventoryComplianceIntegration(inventory_path, profile)
    results = integration.run_inventory_compliance_validation(
        inventory_data=inventory_data,
        services_filter=services_filter
    )
    
    # Ask about saving
    save_choice = input("\n💾 Save results to file? (y/N): ").strip().lower()
    if save_choice in ['y', 'yes']:
        output_path = input("Output file (press Enter for auto-generated): ").strip()
        if not output_path:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_path = f"compliance_results_{timestamp}.json"
        
        integration.save_results(results, output_path)
    
    return results

def run_mode_test(args) -> Dict[str, Any]:
    """Run test mode."""
    print("🧪 RUNNING TEST MODE")
    
    if args.quick:
        # Run quick test
        success = quick_test_integration()
        return {'test_mode': 'quick', 'success': success}
    else:
        # Run comprehensive test
        print("🔬 RUNNING COMPREHENSIVE INTEGRATION TEST")
        print("-" * 50)
        
        test_results = {
            'test_mode': 'comprehensive',
            'tests_run': 0,
            'tests_passed': 0,
            'test_details': {}
        }
        
        # Test 1: Registry functionality
        print("\n1️⃣ Testing Compliance Function Registry...")
        try:
            registry = ComplianceFunctionRegistry()
            stats = registry.get_registry_stats()
            
            assert stats['total_functions'] > 0, "No functions in registry"
            assert len(registry.get_all_services()) > 0, "No services found"
            
            test_results['tests_run'] += 1
            test_results['tests_passed'] += 1
            test_results['test_details']['registry'] = 'PASSED'
            print("   ✅ Registry test PASSED")
            
        except Exception as e:
            test_results['tests_run'] += 1
            test_results['test_details']['registry'] = f'FAILED: {e}'
            print(f"   ❌ Registry test FAILED: {e}")
        
        # Test 2: Integration functionality
        print("\n2️⃣ Testing Integration Functionality...")
        try:
            integration = InventoryComplianceIntegration()
            mock_data = integration._create_mock_inventory()
            
            assert 'services' in mock_data, "Mock data missing services"
            assert len(mock_data['services']) > 0, "No services in mock data"
            
            test_results['tests_run'] += 1
            test_results['tests_passed'] += 1
            test_results['test_details']['integration'] = 'PASSED'
            print("   ✅ Integration test PASSED")
            
        except Exception as e:
            test_results['tests_run'] += 1
            test_results['test_details']['integration'] = f'FAILED: {e}'
            print(f"   ❌ Integration test FAILED: {e}")
        
        # Test 3: End-to-end workflow
        print("\n3️⃣ Testing End-to-End Workflow...")
        try:
            integration = InventoryComplianceIntegration()
            results = integration.run_inventory_compliance_validation()
            
            required_keys = ['metadata', 'execution_summary', 'service_results']
            assert all(key in results for key in required_keys), "Missing required result keys"
            
            test_results['tests_run'] += 1
            test_results['tests_passed'] += 1
            test_results['test_details']['end_to_end'] = 'PASSED'
            print("   ✅ End-to-end test PASSED")
            
        except Exception as e:
            test_results['tests_run'] += 1
            test_results['test_details']['end_to_end'] = f'FAILED: {e}'
            print(f"   ❌ End-to-end test FAILED: {e}")
        
        # Calculate success rate
        success_rate = (test_results['tests_passed'] / test_results['tests_run']) * 100
        test_results['success_rate'] = success_rate
        
        print(f"\n📊 TEST SUMMARY:")
        print(f"   Tests Run: {test_results['tests_run']}")
        print(f"   Tests Passed: {test_results['tests_passed']}")
        print(f"   Success Rate: {success_rate:.1f}%")
        
        if success_rate == 100:
            print("🎉 ALL TESTS PASSED!")
        elif success_rate >= 80:
            print("✅ Most tests passed")
        else:
            print("⚠️  Multiple test failures")
        
        return test_results

def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Inventory-Compliance Integration Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run with defaults (auto-detect inventory)
  python main_runner.py

  # Run with specific inventory file
  python main_runner.py --file /path/to/inventory.json

  # Run interactively
  python main_runner.py --interactive

  # Run with service filter
  python main_runner.py --services s3,ec2 --profile my-profile

  # List available functions
  python main_runner.py --list-functions

  # Run tests
  python main_runner.py --test
  python main_runner.py --test --quick

  # Run with output
  python main_runner.py --save --output my_results.json
        """
    )
    
    # Execution modes
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument('--file', '-f', 
                           help='Path to inventory JSON file')
    mode_group.add_argument('--interactive', '-i', action='store_true',
                           help='Run in interactive mode')
    mode_group.add_argument('--test', '-t', action='store_true',
                           help='Run test suite')
    mode_group.add_argument('--list-functions', '-l', action='store_true',
                           help='List available compliance functions')
    
    # Filters and options
    parser.add_argument('--services', '-s',
                       help='Comma-separated list of services to check')
    parser.add_argument('--functions',
                       help='Comma-separated list of functions to run')
    parser.add_argument('--profile', '-p',
                       help='AWS profile to use')
    
    # Output options
    parser.add_argument('--save', action='store_true',
                       help='Save results to file')
    parser.add_argument('--output', '-o',
                       help='Output file path')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose logging')
    
    # Test options
    parser.add_argument('--quick', action='store_true',
                       help='Run quick test only (use with --test)')
    
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(args.verbose)
    
    # Print banner
    print_banner()
    
    try:
        # Determine execution mode
        if args.list_functions:
            list_available_functions()
            return
        
        elif args.test:
            results = run_mode_test(args)
            
        elif args.interactive:
            results = run_mode_interactive(args)
            
        elif args.file:
            results = run_mode_file(args)
            
        else:
            results = run_mode_default(args)
        
        # Print summary (except for test mode which handles its own summary)
        if not args.test:
            print_execution_summary(results)
    
    except KeyboardInterrupt:
        print("\n\n⏹️  Execution interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Execution failed: {str(e)}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

def print_execution_summary(results: Dict[str, Any]):
    """Print execution summary."""
    print(f"\n{'='*60}")
    print("📊 EXECUTION SUMMARY")
    print(f"{'='*60}")
    
    if 'execution_summary' in results:
        summary = results['execution_summary']
        print(f"Services Found: {summary.get('total_services_found', 0)}")
        print(f"Services with Compliance: {summary.get('services_with_compliance', 0)}")
        print(f"Functions Executed: {summary.get('total_functions_executed', 0)}")
        print(f"Resources Checked: {summary.get('total_resources_checked', 0)}")
        print(f"Total Findings: {len(results.get('all_findings', []))}")
        print(f"Compliance Score: {summary.get('overall_compliance_score', 0):.1f}%")
        
        if results.get('execution_errors'):
            print(f"⚠️  Execution Errors: {len(results['execution_errors'])}")
    
    elif 'test_mode' in results:
        if results['test_mode'] == 'quick':
            print(f"Quick Test: {'PASSED' if results['success'] else 'FAILED'}")
        else:
            test_results = results
            total = test_results['tests_run']
            passed = test_results['tests_passed']
            print(f"Comprehensive Test Suite: {passed}/{total} tests passed ({(passed/total)*100:.1f}%)")

# Convenience functions for direct import usage
def quick_run(inventory_path: Optional[str] = None, 
              services: Optional[List[str]] = None,
              profile: Optional[str] = None) -> Dict[str, Any]:
    """Quick run function for programmatic usage."""
    if inventory_path:
        return run_from_inventory_file(inventory_path, profile, services)
    else:
        integration = InventoryComplianceIntegration(profile_name=profile)
        return integration.run_inventory_compliance_validation(services_filter=services)

def run_compliance_for_service(service_name: str, 
                              inventory_path: Optional[str] = None,
                              profile: Optional[str] = None) -> Dict[str, Any]:
    """Run compliance checks for a specific service only."""
    return quick_run(inventory_path, [service_name], profile)

if __name__ == '__main__':
    main()
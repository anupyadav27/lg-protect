#!/usr/bin/env python3
"""
Quality Assurance Script for AWS Compliance Services

This script validates the quality of service implementations and provides
detailed feedback for developers.
"""

import os
import ast
import importlib
import sys
from typing import List, Dict, Tuple, Set
from pathlib import Path


class QualityChecker:
    """Quality checker for AWS compliance services"""
    
    def __init__(self):
        self.errors = []
        self.warnings = []
        self.passed = []
    
    def check_service_file(self, service_path: str) -> Dict[str, List[str]]:
        """Check a service file for quality issues"""
        service_name = os.path.basename(service_path)
        service_file = os.path.join(service_path, f"{service_name}_service.py")
        
        if not os.path.exists(service_file):
            return {"errors": [f"Service file {service_file} not found"]}
        
        results = {
            "errors": [],
            "warnings": [],
            "passed": []
        }
        
        try:
            with open(service_file, 'r') as f:
                content = f.read()
            
            # Check for prowler dependencies
            if "prowler" in content:
                results["errors"].append("Contains prowler dependencies")
            
            # Check for BaseService import
            if "BaseService" not in content:
                results["errors"].append("Missing BaseService import")
            else:
                results["passed"].append("BaseService imported correctly")
            
            # Check for ComplianceResult import
            if "ComplianceResult" not in content:
                results["errors"].append("Missing ComplianceResult import")
            else:
                results["passed"].append("ComplianceResult imported correctly")
            
            # Check for proper class definition
            if f"class {service_name.title()}Service(BaseService)" not in content:
                results["errors"].append(f"Missing {service_name.title()}Service class definition")
            else:
                results["passed"].append("Service class defined correctly")
            
            # Check for required methods
            if "_get_service_name" not in content:
                results["errors"].append("Missing _get_service_name method")
            else:
                results["passed"].append("_get_service_name method present")
            
            if "_load_resources_for_region" not in content:
                results["errors"].append("Missing _load_resources_for_region method")
            else:
                results["passed"].append("_load_resources_for_region method present")
            
            # Check for proper error handling
            if "try:" in content and "except" in content:
                results["passed"].append("Error handling present")
            else:
                results["warnings"].append("No error handling found")
            
            # Check for logging
            if "logger" in content:
                results["passed"].append("Logging configured")
            else:
                results["warnings"].append("No logging found")
            
            # Check for type hints
            if "->" in content:
                results["passed"].append("Type hints present")
            else:
                results["warnings"].append("No type hints found")
            
        except Exception as e:
            results["errors"].append(f"Error reading file: {e}")
        
        return results
    
    def check_check_files(self, service_path: str) -> Dict[str, List[str]]:
        """Check check files for quality issues"""
        service_name = os.path.basename(service_path)
        results = {
            "errors": [],
            "warnings": [],
            "passed": []
        }
        
        # Find all check directories
        check_dirs = []
        for item in os.listdir(service_path):
            item_path = os.path.join(service_path, item)
            if os.path.isdir(item_path) and not item.startswith('__'):
                check_file = os.path.join(item_path, f"{item}.py")
                if os.path.exists(check_file):
                    check_dirs.append(item)
        
        if not check_dirs:
            results["warnings"].append("No check files found")
            return results
        
        for check_dir in check_dirs:
            check_file = os.path.join(service_path, check_dir, f"{check_dir}.py")
            
            try:
                with open(check_file, 'r') as f:
                    content = f.read()
                
                # Check for prowler dependencies
                if "prowler" in content:
                    results["errors"].append(f"{check_dir}: Contains prowler dependencies")
                
                # Check for BaseCheck import
                if "BaseCheck" not in content:
                    results["errors"].append(f"{check_dir}: Missing BaseCheck import")
                else:
                    results["passed"].append(f"{check_dir}: BaseCheck imported correctly")
                
                # Check for ComplianceResult import
                if "ComplianceResult" not in content:
                    results["errors"].append(f"{check_dir}: Missing ComplianceResult import")
                else:
                    results["passed"].append(f"{check_dir}: ComplianceResult imported correctly")
                
                # Check for service import
                if f"{service_name}_service" not in content:
                    results["errors"].append(f"{check_dir}: Missing service import")
                else:
                    results["passed"].append(f"{check_dir}: Service imported correctly")
                
                # Check for execute method
                if "def execute" not in content:
                    results["errors"].append(f"{check_dir}: Missing execute method")
                else:
                    results["passed"].append(f"{check_dir}: Execute method present")
                
                # Check for proper return type
                if "-> List[ComplianceResult]" in content or "-> list[ComplianceResult]" in content:
                    results["passed"].append(f"{check_dir}: Correct return type")
                else:
                    results["warnings"].append(f"{check_dir}: Return type not specified correctly")
                
            except Exception as e:
                results["errors"].append(f"{check_dir}: Error reading file: {e}")
        
        return results
    
    def check_imports(self, service_path: str) -> Dict[str, List[str]]:
        """Check if imports work correctly"""
        service_name = os.path.basename(service_path)
        results = {
            "errors": [],
            "warnings": [],
            "passed": []
        }
        
        try:
            # Test service import
            sys.path.insert(0, service_path)
            service_module = importlib.import_module(f"{service_name}")
            
            # Test service class import
            service_class_name = f"{service_name.title()}Service"
            if hasattr(service_module, service_class_name):
                results["passed"].append(f"Service class {service_class_name} imported successfully")
            else:
                results["errors"].append(f"Service class {service_class_name} not found in imports")
            
            # Test check imports
            check_imports_working = True
            for item in dir(service_module):
                if not item.startswith('_') and item != service_class_name:
                    try:
                        check_class = getattr(service_module, item)
                        if hasattr(check_class, 'execute'):
                            results["passed"].append(f"Check {item} imported successfully")
                        else:
                            results["warnings"].append(f"Check {item} missing execute method")
                    except Exception as e:
                        results["errors"].append(f"Check {item} import failed: {e}")
                        check_imports_working = False
            
            if check_imports_working:
                results["passed"].append("All check imports working")
            
            sys.path.pop(0)
            
        except Exception as e:
            results["errors"].append(f"Import test failed: {e}")
        
        return results
    
    def generate_report(self, service_path: str) -> str:
        """Generate a comprehensive quality report for a service"""
        service_name = os.path.basename(service_path)
        
        print(f"\n{'='*60}")
        print(f"QUALITY REPORT: {service_name.upper()}")
        print(f"{'='*60}")
        
        # Check service file
        service_results = self.check_service_file(service_path)
        print(f"\n📁 SERVICE FILE ({service_name}_service.py):")
        self._print_results(service_results)
        
        # Check check files
        check_results = self.check_check_files(service_path)
        print(f"\n🔍 CHECK FILES:")
        self._print_results(check_results)
        
        # Check imports
        import_results = self.check_imports(service_path)
        print(f"\n📦 IMPORTS:")
        self._print_results(import_results)
        
        # Summary
        total_errors = len(service_results["errors"]) + len(check_results["errors"]) + len(import_results["errors"])
        total_warnings = len(service_results["warnings"]) + len(check_results["warnings"]) + len(import_results["warnings"])
        total_passed = len(service_results["passed"]) + len(check_results["passed"]) + len(import_results["passed"])
        
        print(f"\n📊 SUMMARY:")
        print(f"✅ Passed: {total_passed}")
        print(f"⚠️  Warnings: {total_warnings}")
        print(f"❌ Errors: {total_errors}")
        
        if total_errors == 0:
            print(f"🎉 {service_name.upper()} PASSES QUALITY CHECKS!")
        else:
            print(f"🔧 {service_name.upper()} NEEDS FIXES!")
        
        return {
            "service": service_name,
            "errors": total_errors,
            "warnings": total_warnings,
            "passed": total_passed
        }
    
    def _print_results(self, results: Dict[str, List[str]]):
        """Print results in a formatted way"""
        for error in results["errors"]:
            print(f"  ❌ {error}")
        
        for warning in results["warnings"]:
            print(f"  ⚠️  {warning}")
        
        for passed in results["passed"]:
            print(f"  ✅ {passed}")
    
    def check_all_services(self) -> List[Dict]:
        """Check all services and generate reports"""
        current_dir = os.getcwd()
        service_dirs = []
        
        for item in os.listdir(current_dir):
            item_path = os.path.join(current_dir, item)
            if os.path.isdir(item_path) and not item.startswith('__') and not item.startswith('.'):
                service_dirs.append(item_path)
        
        service_dirs.sort()
        reports = []
        
        print(f"🔍 CHECKING {len(service_dirs)} SERVICES...")
        
        for service_path in service_dirs:
            report = self.generate_report(service_path)
            reports.append(report)
        
        # Overall summary
        total_errors = sum(r["errors"] for r in reports)
        total_warnings = sum(r["warnings"] for r in reports)
        total_passed = sum(r["passed"] for r in reports)
        
        print(f"\n{'='*60}")
        print(f"OVERALL SUMMARY")
        print(f"{'='*60}")
        print(f"✅ Total Passed: {total_passed}")
        print(f"⚠️  Total Warnings: {total_warnings}")
        print(f"❌ Total Errors: {total_errors}")
        print(f"📁 Services Checked: {len(service_dirs)}")
        
        return reports


def main():
    """Main function"""
    checker = QualityChecker()
    
    if len(sys.argv) > 1:
        # Check specific service
        service_name = sys.argv[1]
        service_path = os.path.join(os.getcwd(), service_name)
        
        if os.path.exists(service_path):
            checker.generate_report(service_path)
        else:
            print(f"❌ Service {service_name} not found")
    else:
        # Check all services
        checker.check_all_services()


if __name__ == "__main__":
    main() 
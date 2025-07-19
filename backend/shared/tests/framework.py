"""
Centralized Test Framework Core - Test Runner and Execution Engine
Enterprise-grade test execution with parallel processing and comprehensive reporting
"""

import asyncio
import pytest
import sys
import os
import time
import subprocess
from pathlib import Path
from typing import List, Dict, Any, Optional, Callable
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed
import json

# Import logging from our centralized logging system
sys.path.append(str(Path(__file__).parent.parent.parent))
from logging.logger import get_logger
from tests.config import get_test_config, setup_test_environment

# Initialize logger
logger = get_logger("test-framework", "runner")

@dataclass
class TestResult:
    """Test execution result"""
    test_type: str
    service: str
    test_file: str
    status: str  # passed, failed, skipped, error
    duration_seconds: float
    error_message: Optional[str] = None
    details: Optional[Dict[str, Any]] = None

@dataclass
class TestSuite:
    """Test suite configuration"""
    name: str
    test_type: str
    test_paths: List[Path]
    parallel: bool = True
    timeout_seconds: int = 300
    retry_count: int = 1

class TestRunner:
    """
    Centralized test runner for LG-Protect CSPM platform
    Handles test discovery, execution, and reporting
    """
    
    def __init__(self, service_name: str = "all"):
        self.service_name = service_name
        self.config = get_test_config()
        self.test_base_path = Path(__file__).parent.parent.parent.parent / "tests"
        self.results: List[TestResult] = []
        self.start_time = None
        self.end_time = None
        
        # Ensure test environment is set up
        setup_test_environment()
        
        logger.info("Test runner initialized", extra_data={
            "service": service_name,
            "test_base_path": str(self.test_base_path),
            "config_valid": len(self.config.validate_configuration()) == 0
        })
    
    def discover_tests(self, test_type: str = "all") -> List[TestSuite]:
        """Discover all test files based on test type and service"""
        test_suites = []
        
        if test_type in ["all", "unit"]:
            unit_tests = self._discover_unit_tests()
            if unit_tests:
                test_suites.append(unit_tests)
        
        if test_type in ["all", "integration"]:
            integration_tests = self._discover_integration_tests()
            if integration_tests:
                test_suites.append(integration_tests)
        
        if test_type in ["all", "e2e"]:
            e2e_tests = self._discover_e2e_tests()
            if e2e_tests:
                test_suites.append(e2e_tests)
        
        if test_type in ["all", "performance"]:
            performance_tests = self._discover_performance_tests()
            if performance_tests:
                test_suites.append(performance_tests)
        
        if test_type in ["all", "security"]:
            security_tests = self._discover_security_tests()
            if security_tests:
                test_suites.append(security_tests)
        
        if test_type in ["all", "compliance"]:
            compliance_tests = self._discover_compliance_tests()
            if compliance_tests:
                test_suites.append(compliance_tests)
        
        logger.info("Test discovery completed", extra_data={
            "test_type": test_type,
            "service": self.service_name,
            "test_suites_found": len(test_suites),
            "total_test_files": sum(len(suite.test_paths) for suite in test_suites)
        })
        
        return test_suites
    
    def _discover_unit_tests(self) -> Optional[TestSuite]:
        """Discover unit tests"""
        unit_path = self.test_base_path / "unit"
        test_paths = self._find_test_files(unit_path)
        
        if test_paths:
            return TestSuite(
                name="Unit Tests",
                test_type="unit",
                test_paths=test_paths,
                parallel=True,
                timeout_seconds=self.config.execution_config['timeout_seconds']
            )
        return None
    
    def _discover_integration_tests(self) -> Optional[TestSuite]:
        """Discover integration tests"""
        integration_path = self.test_base_path / "integration"
        test_paths = self._find_test_files(integration_path)
        
        if test_paths:
            return TestSuite(
                name="Integration Tests",
                test_type="integration",
                test_paths=test_paths,
                parallel=False,  # Integration tests often need sequential execution
                timeout_seconds=self.config.execution_config['timeout_seconds'] * 2
            )
        return None
    
    def _discover_e2e_tests(self) -> Optional[TestSuite]:
        """Discover end-to-end tests"""
        e2e_path = self.test_base_path / "e2e"
        test_paths = self._find_test_files(e2e_path)
        
        if test_paths:
            return TestSuite(
                name="End-to-End Tests",
                test_type="e2e",
                test_paths=test_paths,
                parallel=False,  # E2E tests usually need sequential execution
                timeout_seconds=self.config.execution_config['timeout_seconds'] * 3
            )
        return None
    
    def _discover_performance_tests(self) -> Optional[TestSuite]:
        """Discover performance tests"""
        performance_path = self.test_base_path / "performance"
        test_paths = self._find_test_files(performance_path)
        
        if test_paths:
            return TestSuite(
                name="Performance Tests",
                test_type="performance",
                test_paths=test_paths,
                parallel=False,  # Performance tests need isolated execution
                timeout_seconds=self.config.execution_config['timeout_seconds'] * 4
            )
        return None
    
    def _discover_security_tests(self) -> Optional[TestSuite]:
        """Discover security tests"""
        security_path = self.test_base_path / "security"
        test_paths = self._find_test_files(security_path)
        
        if test_paths:
            return TestSuite(
                name="Security Tests",
                test_type="security",
                test_paths=test_paths,
                parallel=True,
                timeout_seconds=self.config.execution_config['timeout_seconds'] * 2
            )
        return None
    
    def _discover_compliance_tests(self) -> Optional[TestSuite]:
        """Discover compliance tests"""
        compliance_path = self.test_base_path / "compliance"
        test_paths = self._find_test_files(compliance_path)
        
        if test_paths:
            return TestSuite(
                name="Compliance Tests",
                test_type="compliance",
                test_paths=test_paths,
                parallel=True,
                timeout_seconds=self.config.execution_config['timeout_seconds'] * 2
            )
        return None
    
    def _find_test_files(self, base_path: Path) -> List[Path]:
        """Find all test files in a directory"""
        if not base_path.exists():
            return []
        
        test_files = []
        
        # Find Python test files
        for pattern in ["test_*.py", "*_test.py"]:
            test_files.extend(base_path.rglob(pattern))
        
        # Filter by service if specified
        if self.service_name != "all":
            service_filtered = []
            for test_file in test_files:
                if self.service_name in str(test_file):
                    service_filtered.append(test_file)
            test_files = service_filtered
        
        return sorted(test_files)
    
    def run_all_tests(self) -> Dict[str, Any]:
        """Run all discovered tests"""
        logger.info("Starting comprehensive test execution", extra_data={
            "service": self.service_name
        })
        
        self.start_time = time.time()
        test_suites = self.discover_tests("all")
        
        if not test_suites:
            logger.warning("No test suites found")
            return self._generate_empty_report()
        
        # Execute test suites
        for suite in test_suites:
            self._execute_test_suite(suite)
        
        self.end_time = time.time()
        
        # Generate comprehensive report
        report = self._generate_report()
        
        logger.info("Test execution completed", extra_data={
            "total_duration_seconds": self.end_time - self.start_time,
            "total_tests": len(self.results),
            "passed_tests": len([r for r in self.results if r.status == "passed"]),
            "failed_tests": len([r for r in self.results if r.status == "failed"]),
            "test_suites": len(test_suites)
        })
        
        return report
    
    def run_unit_tests(self) -> Dict[str, Any]:
        """Run only unit tests"""
        return self._run_test_type("unit")
    
    def run_integration_tests(self) -> Dict[str, Any]:
        """Run only integration tests"""
        return self._run_test_type("integration")
    
    def run_e2e_tests(self) -> Dict[str, Any]:
        """Run only end-to-end tests"""
        return self._run_test_type("e2e")
    
    def run_performance_tests(self) -> Dict[str, Any]:
        """Run only performance tests"""
        return self._run_test_type("performance")
    
    def run_security_tests(self) -> Dict[str, Any]:
        """Run only security tests"""
        return self._run_test_type("security")
    
    def run_compliance_tests(self) -> Dict[str, Any]:
        """Run only compliance tests"""
        return self._run_test_type("compliance")
    
    def _run_test_type(self, test_type: str) -> Dict[str, Any]:
        """Run specific type of tests"""
        logger.info(f"Starting {test_type} test execution", extra_data={
            "service": self.service_name,
            "test_type": test_type
        })
        
        self.start_time = time.time()
        test_suites = self.discover_tests(test_type)
        
        if not test_suites:
            logger.warning(f"No {test_type} test suites found")
            return self._generate_empty_report()
        
        # Execute test suites
        for suite in test_suites:
            self._execute_test_suite(suite)
        
        self.end_time = time.time()
        
        return self._generate_report()
    
    def _execute_test_suite(self, suite: TestSuite):
        """Execute a test suite"""
        logger.info(f"Executing test suite: {suite.name}", extra_data={
            "test_type": suite.test_type,
            "test_count": len(suite.test_paths),
            "parallel": suite.parallel,
            "timeout": suite.timeout_seconds
        })
        
        if suite.parallel and len(suite.test_paths) > 1:
            self._execute_parallel_tests(suite)
        else:
            self._execute_sequential_tests(suite)
    
    def _execute_parallel_tests(self, suite: TestSuite):
        """Execute tests in parallel"""
        max_workers = min(self.config.execution_config['parallel_workers'], len(suite.test_paths))
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_test = {
                executor.submit(self._execute_single_test, test_path, suite): test_path
                for test_path in suite.test_paths
            }
            
            for future in as_completed(future_to_test):
                test_path = future_to_test[future]
                try:
                    result = future.result(timeout=suite.timeout_seconds)
                    self.results.append(result)
                except Exception as e:
                    error_result = TestResult(
                        test_type=suite.test_type,
                        service=self.service_name,
                        test_file=str(test_path),
                        status="error",
                        duration_seconds=0,
                        error_message=str(e)
                    )
                    self.results.append(error_result)
                    logger.error("Test execution failed", exception=e, extra_data={
                        "test_file": str(test_path),
                        "test_type": suite.test_type
                    })
    
    def _execute_sequential_tests(self, suite: TestSuite):
        """Execute tests sequentially"""
        for test_path in suite.test_paths:
            try:
                result = self._execute_single_test(test_path, suite)
                self.results.append(result)
            except Exception as e:
                error_result = TestResult(
                    test_type=suite.test_type,
                    service=self.service_name,
                    test_file=str(test_path),
                    status="error",
                    duration_seconds=0,
                    error_message=str(e)
                )
                self.results.append(error_result)
                logger.error("Test execution failed", exception=e, extra_data={
                    "test_file": str(test_path),
                    "test_type": suite.test_type
                })
    
    def _execute_single_test(self, test_path: Path, suite: TestSuite) -> TestResult:
        """Execute a single test file"""
        start_time = time.time()
        
        try:
            # Build pytest command
            cmd = [
                sys.executable, "-m", "pytest",
                str(test_path),
                "-v",
                "--tb=short",
                "--json-report",
                f"--json-report-file={self.test_base_path / 'reports' / f'{test_path.stem}_result.json'}"
            ]
            
            # Add coverage if enabled
            if self.config.coverage_config.get('include_branches', False):
                cmd.extend([
                    "--cov=backend",
                    "--cov-report=term-missing"
                ])
            
            # Execute test
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=suite.timeout_seconds,
                cwd=self.test_base_path.parent
            )
            
            duration = time.time() - start_time
            
            # Determine status
            if result.returncode == 0:
                status = "passed"
                error_message = None
            elif result.returncode == 5:  # No tests collected
                status = "skipped"
                error_message = "No tests collected"
            else:
                status = "failed"
                error_message = result.stderr or result.stdout
            
            test_result = TestResult(
                test_type=suite.test_type,
                service=self.service_name,
                test_file=str(test_path),
                status=status,
                duration_seconds=duration,
                error_message=error_message,
                details={
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                    "return_code": result.returncode
                }
            )
            
            logger.info("Test execution completed", extra_data={
                "test_file": str(test_path),
                "status": status,
                "duration_seconds": duration,
                "test_type": suite.test_type
            })
            
            return test_result
            
        except subprocess.TimeoutExpired:
            duration = time.time() - start_time
            error_result = TestResult(
                test_type=suite.test_type,
                service=self.service_name,
                test_file=str(test_path),
                status="timeout",
                duration_seconds=duration,
                error_message=f"Test timed out after {suite.timeout_seconds} seconds"
            )
            
            logger.warning("Test timed out", extra_data={
                "test_file": str(test_path),
                "timeout_seconds": suite.timeout_seconds,
                "test_type": suite.test_type
            })
            
            return error_result
    
    def _generate_report(self) -> Dict[str, Any]:
        """Generate comprehensive test execution report"""
        total_duration = self.end_time - self.start_time if self.end_time and self.start_time else 0
        
        # Calculate statistics
        stats = {
            "total": len(self.results),
            "passed": len([r for r in self.results if r.status == "passed"]),
            "failed": len([r for r in self.results if r.status == "failed"]),
            "skipped": len([r for r in self.results if r.status == "skipped"]),
            "errors": len([r for r in self.results if r.status == "error"]),
            "timeouts": len([r for r in self.results if r.status == "timeout"])
        }
        
        # Calculate success rate
        success_rate = (stats["passed"] / stats["total"] * 100) if stats["total"] > 0 else 0
        
        # Group results by test type
        results_by_type = {}
        for result in self.results:
            if result.test_type not in results_by_type:
                results_by_type[result.test_type] = []
            results_by_type[result.test_type].append(result)
        
        report = {
            "execution_summary": {
                "service": self.service_name,
                "start_time": self.start_time,
                "end_time": self.end_time,
                "total_duration_seconds": total_duration,
                "success_rate_percent": round(success_rate, 2)
            },
            "statistics": stats,
            "results_by_type": results_by_type,
            "failed_tests": [r for r in self.results if r.status in ["failed", "error", "timeout"]],
            "performance_metrics": {
                "average_test_duration": sum(r.duration_seconds for r in self.results) / len(self.results) if self.results else 0,
                "slowest_tests": sorted(self.results, key=lambda r: r.duration_seconds, reverse=True)[:5]
            }
        }
        
        # Save report to file
        self._save_report(report)
        
        return report
    
    def _generate_empty_report(self) -> Dict[str, Any]:
        """Generate report when no tests are found"""
        return {
            "execution_summary": {
                "service": self.service_name,
                "start_time": time.time(),
                "end_time": time.time(),
                "total_duration_seconds": 0,
                "success_rate_percent": 0
            },
            "statistics": {
                "total": 0,
                "passed": 0,
                "failed": 0,
                "skipped": 0,
                "errors": 0,
                "timeouts": 0
            },
            "message": "No tests found for the specified criteria"
        }
    
    def _save_report(self, report: Dict[str, Any]):
        """Save test report to file"""
        reports_dir = self.test_base_path / "reports"
        reports_dir.mkdir(parents=True, exist_ok=True)
        
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        report_file = reports_dir / f"test_report_{self.service_name}_{timestamp}.json"
        
        try:
            with open(report_file, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            
            logger.info("Test report saved", extra_data={
                "report_file": str(report_file),
                "service": self.service_name
            })
        except Exception as e:
            logger.error("Failed to save test report", exception=e, extra_data={
                "report_file": str(report_file)
            })

# Utility functions for direct usage
def run_tests(service_name: str = "all", test_type: str = "all") -> Dict[str, Any]:
    """Convenience function to run tests"""
    runner = TestRunner(service_name)
    
    if test_type == "unit":
        return runner.run_unit_tests()
    elif test_type == "integration":
        return runner.run_integration_tests()
    elif test_type == "e2e":
        return runner.run_e2e_tests()
    elif test_type == "performance":
        return runner.run_performance_tests()
    elif test_type == "security":
        return runner.run_security_tests()
    elif test_type == "compliance":
        return runner.run_compliance_tests()
    else:
        return runner.run_all_tests()

def get_test_status(service_name: str = "all") -> Dict[str, Any]:
    """Get current test status and recent results"""
    runner = TestRunner(service_name)
    test_suites = runner.discover_tests("all")
    
    # Get latest report if available
    reports_dir = runner.test_base_path / "reports"
    latest_report = None
    
    if reports_dir.exists():
        report_files = list(reports_dir.glob(f"test_report_{service_name}_*.json"))
        if report_files:
            latest_report_file = max(report_files, key=lambda f: f.stat().st_mtime)
            try:
                with open(latest_report_file, 'r') as f:
                    latest_report = json.load(f)
            except Exception as e:
                logger.error("Failed to load latest report", exception=e)
    
    return {
        "test_discovery": {
            "total_suites": len(test_suites),
            "total_test_files": sum(len(suite.test_paths) for suite in test_suites),
            "suites": [{"name": suite.name, "test_count": len(suite.test_paths)} for suite in test_suites]
        },
        "latest_execution": latest_report
    }
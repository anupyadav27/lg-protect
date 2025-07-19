#!/usr/bin/env python3
"""
Main Entry Point for Kubernetes Security Scanner

This is the main function that orchestrates the entire security scanning process.
It uses the engine to scan all services and generates comprehensive reports.
"""

import sys
import os
import argparse
from typing import Dict, Any, List
from datetime import datetime

# Add current directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from utility.cluster_namespace_discovery import discover_kubernetes_inventory
from utility.base_reporting import create_reporter, CheckResult, CheckStatus, CheckSeverity
from engine import KubernetesSecurityEngine


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Kubernetes Security Scanner - Comprehensive security checks for Kubernetes clusters"
    )
    
    parser.add_argument(
        "--kubeconfig",
        type=str,
        help="Path to kubeconfig file (default: use default config)"
    )
    
    parser.add_argument(
        "--context",
        type=str,
        help="Kubernetes context to use"
    )
    
    parser.add_argument(
        "--components",
        nargs="+",
        choices=["apiserver", "core", "kubelet", "etcd", "rbac", "scheduler", "controllermanager", "all"],
        default=["all"],
        help="Components to scan (default: all)"
    )
    
    parser.add_argument(
        "--namespaces",
        nargs="+",
        help="Specific namespaces to scan (default: all namespaces)"
    )
    
    parser.add_argument(
        "--output-dir",
        type=str,
        default="./reports",
        help="Output directory for reports (default: ./reports)"
    )
    
    parser.add_argument(
        "--output-format",
        nargs="+",
        choices=["json", "csv", "text", "html"],
        default=["text"],
        help="Output formats for reports (default: text)"
    )
    
    parser.add_argument(
        "--include-nodes",
        action="store_true",
        default=True,
        help="Include node information in discovery (default: True)"
    )
    
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose output"
    )
    
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Perform discovery only, don't run security checks"
    )
    
    return parser.parse_args()


def setup_output_directory(output_dir: str) -> str:
    """Create output directory if it doesn't exist."""
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        print(f"Created output directory: {output_dir}")
    return output_dir


def generate_report_filename(base_name: str, format_type: str, output_dir: str) -> str:
    """Generate a filename for the report."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{base_name}_{timestamp}.{format_type}"
    return os.path.join(output_dir, filename)


def main():
    """Main function that orchestrates the security scanning process."""
    print("=" * 80)
    print("KUBERNETES SECURITY SCANNER")
    print("=" * 80)
    
    # Parse arguments
    args = parse_arguments()
    
    try:
        # Setup output directory
        output_dir = setup_output_directory(args.output_dir)
        
        # Step 1: Discover cluster and namespace inventory
        print("\n🔍 Discovering cluster and namespace inventory...")
        cluster_inventory = discover_kubernetes_inventory(
            kubeconfig=args.kubeconfig,
            context=args.context,
            include_nodes=args.include_nodes
        )
        
        if args.verbose:
            print(f"Cluster Info: {cluster_inventory['cluster_info']}")
            print(f"Found {len(cluster_inventory['namespaces'])} namespaces")
            print(f"Found {len(cluster_inventory['nodes'])} nodes")
        
        # Step 2: Create reporter with cluster info
        reporter = create_reporter(cluster_inventory['cluster_info'])
        
        # Step 3: Initialize security engine
        print("\n🚀 Initializing security engine...")
        engine = KubernetesSecurityEngine(
            cluster_inventory=cluster_inventory,
            kubeconfig=args.kubeconfig,
            context=args.context,
            verbose=args.verbose
        )
        
        if args.dry_run:
            print("\n✅ Dry run completed - Discovery only")
            print(f"Cluster: {cluster_inventory['cluster_info'].get('git_version', 'Unknown')}")
            print(f"Namespaces: {len(cluster_inventory['namespaces'])}")
            print(f"Nodes: {len(cluster_inventory['nodes'])}")
            return 0
        
        # Step 4: Run security checks
        print("\n🔒 Running security checks...")
        
        # Determine which components to scan
        if "all" in args.components:
            components_to_scan = ["apiserver", "core", "kubelet", "etcd", "rbac", "scheduler", "controllermanager"]
        else:
            components_to_scan = args.components
        
        # Filter namespaces if specified
        target_namespaces = None
        if args.namespaces:
            target_namespaces = args.namespaces
            if args.verbose:
                print(f"Target namespaces: {target_namespaces}")
        
        # Run checks for each component
        total_results = []
        for component in components_to_scan:
            print(f"\n📋 Scanning {component}...")
            try:
                component_results = engine.run_component_checks(
                    component=component,
                    namespaces=target_namespaces
                )
                total_results.extend(component_results)
                
                if args.verbose:
                    passed = len([r for r in component_results if r.status == CheckStatus.PASS])
                    failed = len([r for r in component_results if r.status == CheckStatus.FAIL])
                    print(f"  {component}: {passed} passed, {failed} failed")
                    
            except Exception as e:
                print(f"  ❌ Error scanning {component}: {e}")
                # Add error result
                error_result = CheckResult(
                    check_id=f"{component}_scan_error",
                    check_name=f"{component.title()} Scan Error",
                    status=CheckStatus.ERROR,
                    status_extended=f"Failed to scan {component}: {str(e)}",
                    resource_id=component,
                    resource_name=component,
                    resource_type="Component",
                    severity=CheckSeverity.HIGH
                )
                total_results.append(error_result)
        
        # Step 5: Add all results to reporter
        reporter.add_results(total_results)
        
        # Step 6: Generate reports
        print(f"\n📊 Generating reports in {output_dir}...")
        
        cluster_name = cluster_inventory['cluster_info'].get('git_version', 'unknown').replace(':', '_').replace('/', '_')
        base_filename = f"kubernetes_security_report_{cluster_name}"
        
        for format_type in args.output_format:
            filename = generate_report_filename(base_filename, format_type, output_dir)
            
            if format_type == "json":
                reporter.generate_json_report(filename)
            elif format_type == "csv":
                reporter.generate_csv_report(filename)
            elif format_type == "text":
                reporter.generate_text_report(filename)
            elif format_type == "html":
                reporter.generate_html_report(filename)
            
            print(f"  ✅ Generated {format_type.upper()} report: {filename}")
        
        # Step 7: Print summary to console
        print("\n" + "=" * 80)
        print("SCAN COMPLETED")
        print("=" * 80)
        
        summary = reporter.generate_summary()
        print(f"Total Checks: {summary.total_checks}")
        print(f"Passed: {summary.passed}")
        print(f"Failed: {summary.failed}")
        print(f"Errors: {summary.errors}")
        print(f"Execution Time: {summary.execution_time:.2f} seconds")
        
        if summary.failed > 0:
            print(f"\n⚠️  {summary.failed} checks failed - Review the reports for details")
            return 1
        else:
            print("\n✅ All checks passed!")
            return 0
            
    except KeyboardInterrupt:
        print("\n\n❌ Scan interrupted by user")
        return 130
    except Exception as e:
        print(f"\n❌ Fatal error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())

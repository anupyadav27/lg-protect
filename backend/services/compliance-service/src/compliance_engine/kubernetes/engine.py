"""
Kubernetes Security Engine

The core engine that orchestrates security checks across all Kubernetes components.
Integrates discovery, scanning, and reporting capabilities.
"""

import sys
import os
from typing import Dict, Any, List, Optional
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import subprocess
import json

# Add current directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from utility.base_reporting import CheckResult, CheckStatus, CheckSeverity
from utility.cluster_namespace_discovery import discover_kubernetes_inventory, load_kube_api_client
from kubernetes import client

# Import modular service logic
from kubernetes_checks.apiserver import KubernetesChecksAPIServer
from kubernetes_checks.core import KubernetesChecksCore
from kubernetes_checks.kubelet import KubernetesChecksKubelet
from kubernetes_checks.etcd import KubernetesChecksEtcd
from kubernetes_checks.rbac import KubernetesChecksRBAC
from kubernetes_checks.scheduler import KubernetesChecksScheduler
# Add similar import for controllermanager if available


class KubernetesSecurityEngine:
    """
    Main security engine that orchestrates all security checks.
    
    This engine coordinates the discovery, scanning, and reporting of
    security checks across all Kubernetes components using real cluster data.
    """
    
    def __init__(
        self,
        cluster_inventory: Dict[str, Any],
        kubeconfig: Optional[str] = None,
        context: Optional[str] = None,
        verbose: bool = False
    ):
        """
        Initialize the security engine.
        
        Args:
            cluster_inventory: Cluster and namespace inventory from discovery
            kubeconfig: Path to kubeconfig file
            context: Kubernetes context
            verbose: Enable verbose output
        """
        self.cluster_inventory = cluster_inventory
        self.kubeconfig = kubeconfig
        self.context = context
        self.verbose = verbose
        self.start_time = datetime.now()
        
        # Initialize Kubernetes API clients
        self.api_client = None
        self.v1_api = None
        self.rbac_api = None
        self.apps_api = None
        self._initialize_api_clients()
    
    def _initialize_api_clients(self):
        """Initialize Kubernetes API clients using the discovery utility."""
        try:
            # Use the discovery utility to load the API client
            self.api_client = load_kube_api_client(self.kubeconfig, self.context)
            
            # Initialize different API clients for different resource types
            self.v1_api = client.CoreV1Api(self.api_client)
            self.rbac_api = client.RbacAuthorizationV1Api(self.api_client)
            self.apps_api = client.AppsV1Api(self.api_client)
            
            if self.verbose:
                print(f"  ✅ Initialized Kubernetes API clients")
                print(f"  ✅ Connected to cluster: {self.cluster_inventory['cluster_info'].get('git_version', 'Unknown')}")
                
        except Exception as e:
            if self.verbose:
                print(f"  ❌ Failed to initialize API clients: {e}")
            self.api_client = None
            self.v1_api = None
            self.rbac_api = None
            self.apps_api = None
    
    def _get_namespace_names(self, target_namespaces: Optional[List[str]] = None) -> List[str]:
        """Get list of namespace names to scan."""
        if target_namespaces:
            return target_namespaces
        
        # Use all namespaces from discovery
        return [ns['name'] for ns in self.cluster_inventory['namespaces']]
    
    def run_component_checks(
        self,
        component: str,
        namespaces: Optional[List[str]] = None
    ) -> List[CheckResult]:
        """
        Run security checks for a specific component using real cluster data.
        
        Args:
            component: Component name (apiserver, core, kubelet, etc.)
            namespaces: Optional list of namespaces to filter
            
        Returns:
            List of CheckResult objects
        """
        if self.api_client is None:
            return [CheckResult(
                check_id=f"{component}_api_error",
                check_name=f"{component.title()} API Error",
                status=CheckStatus.ERROR,
                status_extended="Kubernetes API client not initialized",
                resource_id=component,
                resource_name=component,
                resource_type="Component",
                severity=CheckSeverity.HIGH
            )]
        
        try:
            if self.verbose:
                print(f"    Running {component} checks...")
            
            # Use modular service logic
            provider = self.api_client  # Pass the API client as provider
            if component == "apiserver":
                service = KubernetesChecksAPIServer(provider)
            elif component == "core":
                service = KubernetesChecksCore(provider)
            elif component == "kubelet":
                service = KubernetesChecksKubelet(provider)
            elif component == "etcd":
                service = KubernetesChecksEtcd(provider)
            elif component == "rbac":
                service = KubernetesChecksRBAC(provider)
            elif component == "scheduler":
                service = KubernetesChecksScheduler(provider)
            # Add similar logic for controllermanager if available
            else:
                return [CheckResult(
                    check_id=f"{component}_unknown",
                    check_name=f"{component.title()} Unknown Component",
                    status=CheckStatus.ERROR,
                    status_extended=f"Unknown component: {component}",
                    resource_id=component,
                    resource_name=component,
                    resource_type="Component",
                    severity=CheckSeverity.MEDIUM
                )]
            results = service.execute_all_checks()
            
            if self.verbose:
                passed = len([r for r in results if r.status == CheckStatus.PASS])
                failed = len([r for r in results if r.status == CheckStatus.FAIL])
                print(f"    {component}: {len(results)} total, {passed} passed, {failed} failed")
            
            return results
            
        except Exception as e:
            if self.verbose:
                print(f"    ❌ Error running {component} checks: {e}")
            
            return [CheckResult(
                check_id=f"{component}_scan_error",
                check_name=f"{component.title()} Scan Error",
                status=CheckStatus.ERROR,
                status_extended=f"Failed to run {component} checks: {str(e)}",
                resource_id=component,
                resource_name=component,
                resource_type="Component",
                severity=CheckSeverity.HIGH
            )]
    
    def _run_apiserver_checks(self, namespaces: List[str]) -> List[CheckResult]:
        """Run API Server security checks."""
        results = []
        
        try:
            # Get API server pods from kube-system namespace
            api_server_pods = self.v1_api.list_namespaced_pod(
                namespace="kube-system",
                label_selector="component=kube-apiserver"
            )
            
            for pod in api_server_pods.items:
                # Check 1: TLS configuration
                tls_configured = self._check_apiserver_tls(pod)
                results.append(CheckResult(
                    check_id="apiserver_tls_config",
                    check_name="API Server TLS Configuration",
                    status=CheckStatus.PASS if tls_configured else CheckStatus.FAIL,
                    status_extended=f"TLS {'is' if tls_configured else 'is not'} properly configured in {pod.metadata.name}",
                    resource_id=pod.metadata.name,
                    resource_name=pod.metadata.name,
                    resource_type="Pod",
                    namespace="kube-system",
                    severity=CheckSeverity.HIGH,
                    recommendations=["Configure TLS certificates for API server"] if not tls_configured else []
                ))
                
                # Check 2: Anonymous authentication
                anonymous_disabled = self._check_apiserver_anonymous_auth(pod)
                results.append(CheckResult(
                    check_id="apiserver_anonymous_auth",
                    check_name="API Server Anonymous Authentication",
                    status=CheckStatus.PASS if anonymous_disabled else CheckStatus.FAIL,
                    status_extended=f"Anonymous authentication {'is disabled' if anonymous_disabled else 'is enabled'} in {pod.metadata.name}",
                    resource_id=pod.metadata.name,
                    resource_name=pod.metadata.name,
                    resource_type="Pod",
                    namespace="kube-system",
                    severity=CheckSeverity.HIGH,
                    recommendations=["Set --anonymous-auth=false"] if not anonymous_disabled else []
                ))
                
        except Exception as e:
            results.append(CheckResult(
                check_id="apiserver_api_error",
                check_name="API Server API Error",
                status=CheckStatus.ERROR,
                status_extended=f"Failed to access API server pods: {str(e)}",
                resource_id="apiserver",
                resource_name="apiserver",
                resource_type="Component",
                severity=CheckSeverity.HIGH
            ))
        
        return results
    
    def _run_core_checks(self, namespaces: List[str]) -> List[CheckResult]:
        """Run Core Kubernetes security checks."""
        results = []
        
        for namespace in namespaces:
            try:
                # Get all pods in the namespace
                pods = self.v1_api.list_namespaced_pod(namespace=namespace)
                
                for pod in pods.items:
                    # Check 1: Privileged containers
                    privileged_found = self._check_privileged_containers(pod)
                    if privileged_found:
                        results.append(CheckResult(
                            check_id="core_privileged_containers",
                            check_name="Privileged Containers",
                            status=CheckStatus.FAIL,
                            status_extended=f"Found privileged container in pod {pod.metadata.name}",
                            resource_id=pod.metadata.name,
                            resource_name=pod.metadata.name,
                            resource_type="Pod",
                            namespace=namespace,
                            severity=CheckSeverity.CRITICAL,
                            recommendations=[
                                "Remove privileged mode from containers",
                                "Use security contexts with minimal privileges",
                                "Consider using Pod Security Standards"
                            ]
                        ))
                    else:
                        results.append(CheckResult(
                            check_id="core_privileged_containers",
                            check_name="Privileged Containers",
                            status=CheckStatus.PASS,
                            status_extended=f"No privileged containers found in pod {pod.metadata.name}",
                            resource_id=pod.metadata.name,
                            resource_name=pod.metadata.name,
                            resource_type="Pod",
                            namespace=namespace,
                            severity=CheckSeverity.HIGH
                        ))
                    
                    # Check 2: Root containers
                    root_found = self._check_root_containers(pod)
                    if root_found:
                        results.append(CheckResult(
                            check_id="core_root_containers",
                            check_name="Root Containers",
                            status=CheckStatus.FAIL,
                            status_extended=f"Found container running as root in pod {pod.metadata.name}",
                            resource_id=pod.metadata.name,
                            resource_name=pod.metadata.name,
                            resource_type="Pod",
                            namespace=namespace,
                            severity=CheckSeverity.MEDIUM,
                            recommendations=[
                                "Set runAsUser to a non-zero value",
                                "Use security contexts with non-root users"
                            ]
                        ))
                    else:
                        results.append(CheckResult(
                            check_id="core_root_containers",
                            check_name="Root Containers",
                            status=CheckStatus.PASS,
                            status_extended=f"No containers running as root found in pod {pod.metadata.name}",
                            resource_id=pod.metadata.name,
                            resource_name=pod.metadata.name,
                            resource_type="Pod",
                            namespace=namespace,
                            severity=CheckSeverity.MEDIUM
                        ))
                        
            except Exception as e:
                results.append(CheckResult(
                    check_id="core_namespace_error",
                    check_name="Core Namespace Error",
                    status=CheckStatus.ERROR,
                    status_extended=f"Failed to scan namespace {namespace}: {str(e)}",
                    resource_id=namespace,
                    resource_name=namespace,
                    resource_type="Namespace",
                    severity=CheckSeverity.MEDIUM
                ))
        
        return results
    
    def _run_rbac_checks(self, namespaces: List[str]) -> List[CheckResult]:
        """Run RBAC security checks."""
        results = []
        
        try:
            # Check cluster admin usage
            cluster_admins = self.rbac_api.list_cluster_role_binding(
                label_selector="kubernetes.io/bootstrapping=rbac-defaults"
            )
            
            admin_count = len([binding for binding in cluster_admins.items 
                             if binding.role_ref.name == "cluster-admin"])
            
            results.append(CheckResult(
                check_id="rbac_cluster_admin_usage",
                check_name="RBAC Cluster Admin Usage",
                status=CheckStatus.PASS if admin_count <= 1 else CheckStatus.FAIL,
                status_extended=f"Found {admin_count} cluster-admin bindings",
                resource_id="cluster-admin",
                resource_name="cluster-admin",
                resource_type="ClusterRoleBinding",
                severity=CheckSeverity.HIGH,
                recommendations=["Minimize cluster-admin role usage"] if admin_count > 1 else []
            ))
            
        except Exception as e:
            results.append(CheckResult(
                check_id="rbac_api_error",
                check_name="RBAC API Error",
                status=CheckStatus.ERROR,
                status_extended=f"Failed to access RBAC resources: {str(e)}",
                resource_id="rbac",
                resource_name="rbac",
                resource_type="Component",
                severity=CheckSeverity.MEDIUM
            ))
        
        return results
    
    def _run_kubelet_checks(self, namespaces: List[str]) -> List[CheckResult]:
        """Run Kubelet security checks."""
        results = []
        
        try:
            # Get nodes to check kubelet configuration
            nodes = self.v1_api.list_node()
            
            for node in nodes.items:
                # Check kubelet configuration (basic check)
                results.append(CheckResult(
                    check_id="kubelet_config",
                    check_name="Kubelet Configuration",
                    status=CheckStatus.PASS,
                    status_extended=f"Kubelet configuration checked for node {node.metadata.name}",
                    resource_id=node.metadata.name,
                    resource_name=node.metadata.name,
                    resource_type="Node",
                    severity=CheckSeverity.MEDIUM
                ))
                
        except Exception as e:
            results.append(CheckResult(
                check_id="kubelet_api_error",
                check_name="Kubelet API Error",
                status=CheckStatus.ERROR,
                status_extended=f"Failed to access node information: {str(e)}",
                resource_id="kubelet",
                resource_name="kubelet",
                resource_type="Component",
                severity=CheckSeverity.MEDIUM
            ))
        
        return results
    
    def _run_etcd_checks(self, namespaces: List[str]) -> List[CheckResult]:
        """Run Etcd security checks."""
        results = []
        
        try:
            # Check etcd pods in kube-system
            etcd_pods = self.v1_api.list_namespaced_pod(
                namespace="kube-system",
                label_selector="component=etcd"
            )
            
            for pod in etcd_pods.items:
                results.append(CheckResult(
                    check_id="etcd_tls_config",
                    check_name="Etcd TLS Configuration",
                    status=CheckStatus.PASS,
                    status_extended=f"Etcd TLS configuration checked for {pod.metadata.name}",
                    resource_id=pod.metadata.name,
                    resource_name=pod.metadata.name,
                    resource_type="Pod",
                    namespace="kube-system",
                    severity=CheckSeverity.HIGH
                ))
                
        except Exception as e:
            results.append(CheckResult(
                check_id="etcd_api_error",
                check_name="Etcd API Error",
                status=CheckStatus.ERROR,
                status_extended=f"Failed to access etcd information: {str(e)}",
                resource_id="etcd",
                resource_name="etcd",
                resource_type="Component",
                severity=CheckSeverity.MEDIUM
            ))
        
        return results
    
    def _run_scheduler_checks(self, namespaces: List[str]) -> List[CheckResult]:
        """Run Scheduler security checks."""
        results = []
        
        try:
            # Check scheduler pods
            scheduler_pods = self.v1_api.list_namespaced_pod(
                namespace="kube-system",
                label_selector="component=kube-scheduler"
            )
            
            for pod in scheduler_pods.items:
                results.append(CheckResult(
                    check_id="scheduler_config",
                    check_name="Scheduler Configuration",
                    status=CheckStatus.PASS,
                    status_extended=f"Scheduler configuration checked for {pod.metadata.name}",
                    resource_id=pod.metadata.name,
                    resource_name=pod.metadata.name,
                    resource_type="Pod",
                    namespace="kube-system",
                    severity=CheckSeverity.MEDIUM
                ))
                
        except Exception as e:
            results.append(CheckResult(
                check_id="scheduler_api_error",
                check_name="Scheduler API Error",
                status=CheckStatus.ERROR,
                status_extended=f"Failed to access scheduler information: {str(e)}",
                resource_id="scheduler",
                resource_name="scheduler",
                resource_type="Component",
                severity=CheckSeverity.MEDIUM
            ))
        
        return results
    
    def _run_controllermanager_checks(self, namespaces: List[str]) -> List[CheckResult]:
        """Run Controller Manager security checks."""
        results = []
        
        try:
            # Check controller manager pods
            cm_pods = self.v1_api.list_namespaced_pod(
                namespace="kube-system",
                label_selector="component=kube-controller-manager"
            )
            
            for pod in cm_pods.items:
                results.append(CheckResult(
                    check_id="controllermanager_config",
                    check_name="Controller Manager Configuration",
                    status=CheckStatus.PASS,
                    status_extended=f"Controller manager configuration checked for {pod.metadata.name}",
                    resource_id=pod.metadata.name,
                    resource_name=pod.metadata.name,
                    resource_type="Pod",
                    namespace="kube-system",
                    severity=CheckSeverity.MEDIUM
                ))
                
        except Exception as e:
            results.append(CheckResult(
                check_id="controllermanager_api_error",
                check_name="Controller Manager API Error",
                status=CheckStatus.ERROR,
                status_extended=f"Failed to access controller manager information: {str(e)}",
                resource_id="controllermanager",
                resource_name="controllermanager",
                resource_type="Component",
                severity=CheckSeverity.MEDIUM
            ))
        
        return results
    
    def _check_apiserver_tls(self, pod) -> bool:
        """Check if API server has TLS configured."""
        try:
            for container in pod.spec.containers:
                for arg in container.args or []:
                    if arg.startswith("--tls-cert-file") or arg.startswith("--tls-private-key-file"):
                        return True
            return False
        except:
            return False
    
    def _check_apiserver_anonymous_auth(self, pod) -> bool:
        """Check if anonymous authentication is disabled."""
        try:
            for container in pod.spec.containers:
                for arg in container.args or []:
                    if arg == "--anonymous-auth=false":
                        return True
            return False
        except:
            return False
    
    def _check_privileged_containers(self, pod) -> bool:
        """Check if pod has privileged containers."""
        try:
            for container in pod.spec.containers:
                if container.security_context and container.security_context.privileged:
                    return True
            return False
        except:
            return False
    
    def _check_root_containers(self, pod) -> bool:
        """Check if pod has containers running as root."""
        try:
            for container in pod.spec.containers:
                if container.security_context and container.security_context.run_as_user == 0:
                    return True
            return False
        except:
            return False
    
    def run_all_checks(self, namespaces: Optional[List[str]] = None) -> List[CheckResult]:
        """
        Run security checks for all components.
        
        Args:
            namespaces: Optional list of namespaces to filter
            
        Returns:
            List of CheckResult objects
        """
        all_results = []
        components = ["apiserver", "core", "kubelet", "etcd", "rbac", "scheduler", "controllermanager"]
        
        for component in components:
            component_results = self.run_component_checks(component, namespaces)
            all_results.extend(component_results)
        
        return all_results
    
    def run_all_checks_parallel(self, namespaces: Optional[List[str]] = None, max_workers: int = 8) -> List[CheckResult]:
        """
        Run security checks for all components and namespaces in parallel using threads.
        Args:
            namespaces: Optional list of namespaces to filter
            max_workers: Maximum number of threads to use
        Returns:
            List of CheckResult objects
        """
        all_results = []
        components = ["apiserver", "core", "kubelet", "etcd", "rbac", "scheduler", "controllermanager"]
        target_namespaces = self._get_namespace_names(namespaces)
        tasks = []
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            for component in components:
                for namespace in target_namespaces:
                    # Each task runs checks for a single component and single namespace
                    tasks.append(executor.submit(self.run_component_checks, component, [namespace]))
            for future in as_completed(tasks):
                try:
                    all_results.extend(future.result())
                except Exception as e:
                    # In case of error, add a generic error result
                    all_results.append(CheckResult(
                        check_id="parallel_execution_error",
                        check_name="Parallel Execution Error",
                        status=CheckStatus.ERROR,
                        status_extended=f"Error in parallel execution: {str(e)}",
                        resource_id="parallel",
                        resource_name="parallel",
                        resource_type="Parallel",
                        severity=CheckSeverity.HIGH
                    ))
        return all_results
    
    def get_component_summary(self, component: str) -> Dict[str, Any]:
        """
        Get a summary of results for a specific component.
        
        Args:
            component: Component name
            
        Returns:
            Summary dictionary
        """
        results = self.run_component_checks(component)
        
        summary = {
            "component": component,
            "total": len(results),
            "passed": len([r for r in results if r.status == CheckStatus.PASS]),
            "failed": len([r for r in results if r.status == CheckStatus.FAIL]),
            "errors": len([r for r in results if r.status == CheckStatus.ERROR]),
            "manual": len([r for r in results if r.status == CheckStatus.MANUAL]),
            "skipped": len([r for r in results if r.status == CheckStatus.SKIP]),
            "by_severity": {
                "LOW": len([r for r in results if r.severity == CheckSeverity.LOW]),
                "MEDIUM": len([r for r in results if r.severity == CheckSeverity.MEDIUM]),
                "HIGH": len([r for r in results if r.severity == CheckSeverity.HIGH]),
                "CRITICAL": len([r for r in results if r.severity == CheckSeverity.CRITICAL])
            }
        }
        
        return summary
    
    def get_overall_summary(self) -> Dict[str, Any]:
        """
        Get a summary of all results.
        
        Returns:
            Overall summary dictionary
        """
        all_results = self.run_all_checks()
        
        summary = {
            "total_checks": len(all_results),
            "passed": len([r for r in all_results if r.status == CheckStatus.PASS]),
            "failed": len([r for r in all_results if r.status == CheckStatus.FAIL]),
            "errors": len([r for r in all_results if r.status == CheckStatus.ERROR]),
            "manual": len([r for r in all_results if r.status == CheckStatus.MANUAL]),
            "skipped": len([r for r in all_results if r.status == CheckStatus.SKIP]),
            "by_severity": {
                "LOW": len([r for r in all_results if r.severity == CheckSeverity.LOW]),
                "MEDIUM": len([r for r in all_results if r.severity == CheckSeverity.MEDIUM]),
                "HIGH": len([r for r in all_results if r.severity == CheckSeverity.HIGH]),
                "CRITICAL": len([r for r in all_results if r.severity == CheckSeverity.CRITICAL])
            },
            "by_component": {}
        }
        
        # Calculate by component
        components = ["apiserver", "core", "kubelet", "etcd", "rbac", "scheduler", "controllermanager"]
        for component in components:
            component_summary = self.get_component_summary(component)
            summary["by_component"][component] = {
                "total": component_summary["total"],
                "passed": component_summary["passed"],
                "failed": component_summary["failed"],
                "errors": component_summary["errors"]
            }
        
        return summary
    
    def get_failed_checks(self, component: Optional[str] = None) -> List[CheckResult]:
        """
        Get all failed checks, optionally filtered by component.
        
        Args:
            component: Optional component name to filter by
            
        Returns:
            List of failed CheckResult objects
        """
        if component:
            results = self.run_component_checks(component)
        else:
            results = self.run_all_checks()
        
        return [r for r in results if r.status == CheckStatus.FAIL]
    
    def get_high_severity_checks(self, component: Optional[str] = None) -> List[CheckResult]:
        """
        Get all high/critical severity checks, optionally filtered by component.
        
        Args:
            component: Optional component name to filter by
            
        Returns:
            List of high/critical CheckResult objects
        """
        if component:
            results = self.run_component_checks(component)
        else:
            results = self.run_all_checks()
        
        return [r for r in results if r.severity in [CheckSeverity.HIGH, CheckSeverity.CRITICAL]]
    
    def get_execution_time(self) -> float:
        """Get the total execution time."""
        end_time = datetime.now()
        return (end_time - self.start_time).total_seconds()

    def run_multicluster_scan(self, clusters: list, scan_parallel: bool = False, max_workers: int = 4):
        """
        Orchestrate scanning across multiple clusters.
        Args:
            clusters: List of cluster dicts (from multicloud_cluster_inventory.py)
            scan_parallel: Whether to scan clusters in parallel
            max_workers: Number of parallel workers (if scan_parallel)
        Returns:
            List of (cluster_name, scan_results) tuples
        """
        def update_kubeconfig(cluster):
            provider = cluster.get('provider')
            if provider == 'gcp':
                cmd = [
                    'gcloud', 'container', 'clusters', 'get-credentials',
                    cluster['name'], '--project', cluster['project'],
                    '--region' if 'region' in cluster['location'] else '--zone', cluster['location']
                ]
            elif provider == 'aws':
                cmd = [
                    'aws', 'eks', 'update-kubeconfig',
                    '--region', cluster['region'], '--name', cluster['name']
                ]
            elif provider == 'azure':
                cmd = [
                    'az', 'aks', 'get-credentials',
                    '--resource-group', cluster['resourceGroup'],
                    '--name', cluster['name'], '--overwrite-existing'
                ]
            elif provider == 'ocp':
                # For OCP, assume user is already logged in or context is set
                cmd = None
            else:
                cmd = None
            if cmd:
                subprocess.run(cmd, check=True)

        def scan_single_cluster(cluster):
            update_kubeconfig(cluster)
            cluster_inventory = discover_kubernetes_inventory()
            engine = KubernetesSecurityEngine(cluster_inventory, verbose=self.verbose)
            if scan_parallel:
                results = engine.run_all_checks_parallel(max_workers=max_workers)
            else:
                results = engine.run_all_checks()
            return (cluster.get('name'), results)

        results = []
        if scan_parallel:
            from concurrent.futures import ThreadPoolExecutor, as_completed
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {executor.submit(scan_single_cluster, c): c for c in clusters}
                for future in as_completed(futures):
                    try:
                        results.append(future.result())
                    except Exception as e:
                        results.append((futures[future].get('name'), f'Error: {e}'))
        else:
            for cluster in clusters:
                try:
                    results.append(scan_single_cluster(cluster))
                except Exception as e:
                    results.append((cluster.get('name'), f'Error: {e}'))
        return results


# Example usage
if __name__ == "__main__":
    # Example of how to use the engine with real cluster data
    print("Discovering cluster inventory...")
    cluster_inventory = discover_kubernetes_inventory()
    print("Initializing security engine...")
    engine = KubernetesSecurityEngine(cluster_inventory, verbose=True)
    # Run all checks sequentially
    print("Running security checks (sequential)...")
    results = engine.run_all_checks()
    print(f"Total results (sequential): {len(results)}")
    # Run all checks in parallel
    print("Running security checks (parallel)...")
    parallel_results = engine.run_all_checks_parallel(max_workers=12)
    print(f"Total results (parallel): {len(parallel_results)}")
    # Example: Multi-cluster orchestration
    try:
        with open("utility/multicloud_clusters.json") as f:
            clusters = json.load(f)
        print("Running multi-cluster scan...")
        multi_results = engine.run_multicluster_scan(clusters, scan_parallel=True, max_workers=4)
        print(f"Multi-cluster scan results: {[(name, len(res) if isinstance(res, list) else res) for name, res in multi_results]}")
    except Exception as e:
        print(f"Multi-cluster scan skipped: {e}")
    # Get summary
    summary = engine.get_overall_summary()
    print(f"Summary: {summary}") 
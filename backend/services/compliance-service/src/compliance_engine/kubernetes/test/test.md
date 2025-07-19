Functionality Test List
Cluster Discovery & Inventory
Test GKE cluster discovery via multicloud_cluster_inventory.py
Test EKS cluster discovery via multicloud_cluster_inventory.py
Test AKS cluster discovery via multicloud_cluster_inventory.py
Test OCP cluster discovery via multicloud_cluster_inventory.py
Test output file creation (multicloud_clusters.json) and content validity
Kubeconfig/Context Management
Test kubeconfig update for GKE cluster (via CLI)
Test kubeconfig update for EKS cluster (via CLI)
Test kubeconfig update for AKS cluster (via CLI)
Test kubeconfig/context switch for OCP cluster (manual or CLI)
Test self-managed cluster context selection
Cluster & Namespace Discovery
Test namespace and node discovery for a GKE cluster
Test namespace and node discovery for an EKS cluster
Test namespace and node discovery for an AKS cluster
Test namespace and node discovery for an OCP cluster
Test namespace and node discovery for a self-managed cluster
Engine: Single Cluster
Test engine sequential scan for all 7 services in a single cluster
Test engine parallel scan for all 7 services in a single cluster
Test engine scan for a specific namespace
Test engine scan for a specific service/component
Engine: Multi-Cluster Orchestration
Test multi-cluster scan (sequential) across all discovered clusters
Test multi-cluster scan (parallel) across all discovered clusters
Test aggregation of results from multiple clusters
Reporting
Test JSON report output
Test CSV report output
Test text report output
Test HTML report output
Test summary and per-component reporting
Error Handling
Test behavior with invalid kubeconfig/context
Test behavior with unreachable cluster
Test behavior with missing cloud CLI
Test behavior with no namespaces in a cluster
Test behavior with no nodes in a cluster
Performance
Test scan time for a small cluster
Test scan time for a large cluster
Test scan time for multi-cluster parallel execution

"""
Robust Cluster and Namespace Discovery Utility

Works with any Kubernetes distribution (OCP, GKE, AKS, EKS, ECS, vanilla k8s, etc).
Discovers cluster version, UID, nodes, and namespaces for later use by service/check runners.
"""

from typing import List, Dict, Any, Optional
from kubernetes import client, config
from kubernetes.client.rest import ApiException
import os
import subprocess
import json


def load_kube_api_client(kubeconfig: Optional[str] = None, context: Optional[str] = None, api_client: Optional[client.ApiClient] = None) -> client.ApiClient:
    """
    Load Kubernetes API client using the best available method.
    Order: provided api_client > kubeconfig/context > in-cluster > default kubeconfig
    """
    if api_client:
        return api_client
    try:
        if kubeconfig or context:
            config.load_kube_config(config_file=kubeconfig, context=context)
        else:
            # Try in-cluster first
            try:
                config.load_incluster_config()
            except config.ConfigException:
                config.load_kube_config()
        return client.ApiClient()
    except Exception as e:
        raise RuntimeError(f"Failed to load Kubernetes API client: {e}")


def discover_kubernetes_inventory(
    kubeconfig: str = None,
    context: str = None,
    api_client: client.ApiClient = None,
    include_nodes: bool = True,
    include_extra: bool = False
) -> Dict[str, Any]:
    """
    Robustly discover cluster, node, and namespace inventory for any Kubernetes distribution.
    Returns a dictionary with cluster info, nodes, and namespaces.
    """
    api = load_kube_api_client(kubeconfig, context, api_client)
    v1 = client.CoreV1Api(api)
    version_api = client.VersionApi(api)
    inventory = {
        "cluster_info": {},
        "nodes": [],
        "namespaces": []
    }

    # Cluster info
    try:
        version = version_api.get_code()
        # Try to get cluster UID from kube-system namespace (not always available)
        cluster_uid = None
        try:
            ns = v1.read_namespace("kube-system")
            cluster_uid = ns.metadata.uid
        except Exception:
            pass
        inventory["cluster_info"] = {
            "major": version.major,
            "minor": version.minor,
            "git_version": version.git_version,
            "platform": version.platform,
            "cluster_uid": cluster_uid
        }
    except Exception as e:
        inventory["cluster_info"] = {"error": str(e)}

    # Nodes
    if include_nodes:
        try:
            node_list = v1.list_node()
            for node in node_list.items:
                node_info = {
                    "name": node.metadata.name,
                    "labels": node.metadata.labels or {},
                    "taints": [t.to_dict() for t in (node.spec.taints or [])],
                    "roles": [k.replace("node-role.kubernetes.io/", "") for k in (node.metadata.labels or {}) if k.startswith("node-role.kubernetes.io/")],
                    "internal_ip": None,
                    "external_ip": None,
                    "os_image": node.status.node_info.os_image,
                    "kubelet_version": node.status.node_info.kubelet_version,
                    "container_runtime": node.status.node_info.container_runtime_version
                }
                for addr in node.status.addresses:
                    if addr.type == "InternalIP":
                        node_info["internal_ip"] = addr.address
                    elif addr.type == "ExternalIP":
                        node_info["external_ip"] = addr.address
                inventory["nodes"].append(node_info)
        except ApiException as e:
            inventory["nodes"] = [{"error": str(e)}]

    # Namespaces
    try:
        ns_list = v1.list_namespace()
        for ns in ns_list.items:
            ns_info = {
                "name": ns.metadata.name,
                "labels": ns.metadata.labels or {},
                "annotations": ns.metadata.annotations or {},
                "status": ns.status.phase,
                "creation_timestamp": str(ns.metadata.creation_timestamp),
                "uid": ns.metadata.uid
            }
            inventory["namespaces"].append(ns_info)
    except ApiException as e:
        inventory["namespaces"] = [{"error": str(e)}]

    # Optionally, add extra info (API server endpoints, etc.)
    if include_extra:
        try:
            api_endpoints = []
            for ep in v1.list_endpoints(namespace="default").items:
                api_endpoints.append(ep.metadata.name)
            inventory["extra"] = {"api_endpoints": api_endpoints}
        except Exception:
            inventory["extra"] = {"api_endpoints": []}

    return inventory


def print_inventory(inventory: Dict[str, Any]):
    print("\nCluster Info:")
    for k, v in inventory["cluster_info"].items():
        print(f"  {k}: {v}")
    print("\nNodes:")
    for node in inventory["nodes"]:
        print(f"- {node.get('name')} (roles: {node.get('roles')}, internal_ip: {node.get('internal_ip')})")
    print("\nNamespaces:")
    for ns in inventory["namespaces"]:
        print(f"- {ns['name']} (status: {ns['status']}, created: {ns['creation_timestamp']})")
        if ns["labels"]:
            print(f"    labels: {ns['labels']}")
        if ns.get("annotations"):
            print(f"    annotations: {ns['annotations']}")


def prompt_for_cluster_type():
    print("Select the type of Kubernetes cluster to scan:")
    print("1. GKE (Google Kubernetes Engine)")
    print("2. EKS (Amazon EKS)")
    print("3. AKS (Azure AKS)")
    print("4. OCP (OpenShift)")
    print("5. Self-managed/Other (already in kubeconfig)")
    choice = input("Enter choice [1-5]: ").strip()
    return choice

def select_and_update_kubeconfig():
    choice = prompt_for_cluster_type()
    if choice == "1":
        from utility.multicloud_cluster_inventory import list_gke_clusters
        clusters = list_gke_clusters()
        if not clusters:
            print("No GKE clusters found.")
            return None
        for idx, c in enumerate(clusters):
            print(f"{idx+1}. {c['name']} (project: {c['project']}, location: {c['location']})")
        sel = int(input("Select cluster: ")) - 1
        cluster = clusters[sel]
        cmd = [
            "gcloud", "container", "clusters", "get-credentials",
            cluster["name"], "--project", cluster["project"],
            "--region" if "region" in cluster["location"] else "--zone", cluster["location"]
        ]
        subprocess.run(cmd, check=True)
        print(f"Kubeconfig updated for GKE cluster: {cluster['name']}")
        return cluster["name"]
    elif choice == "2":
        from utility.multicloud_cluster_inventory import list_eks_clusters
        clusters = list_eks_clusters()
        if not clusters:
            print("No EKS clusters found.")
            return None
        for idx, c in enumerate(clusters):
            print(f"{idx+1}. {c['name']} (region: {c['region']})")
        sel = int(input("Select cluster: ")) - 1
        cluster = clusters[sel]
        cmd = [
            "aws", "eks", "update-kubeconfig",
            "--region", cluster["region"], "--name", cluster["name"]
        ]
        subprocess.run(cmd, check=True)
        print(f"Kubeconfig updated for EKS cluster: {cluster['name']}")
        return cluster["name"]
    elif choice == "3":
        from utility.multicloud_cluster_inventory import list_aks_clusters
        clusters = list_aks_clusters()
        if not clusters:
            print("No AKS clusters found.")
            return None
        for idx, c in enumerate(clusters):
            print(f"{idx+1}. {c['name']} (resourceGroup: {c['resourceGroup']})")
        sel = int(input("Select cluster: ")) - 1
        cluster = clusters[sel]
        cmd = [
            "az", "aks", "get-credentials",
            "--resource-group", cluster["resourceGroup"],
            "--name", cluster["name"], "--overwrite-existing"
        ]
        subprocess.run(cmd, check=True)
        print(f"Kubeconfig updated for AKS cluster: {cluster['name']}")
        return cluster["name"]
    elif choice == "4":
        from utility.multicloud_cluster_inventory import list_ocp_clusters
        clusters = list_ocp_clusters()
        if not clusters:
            print("No OCP clusters found.")
            return None
        for idx, c in enumerate(clusters):
            print(f"{idx+1}. {c['name']} (source: {c.get('source', '')})")
        sel = int(input("Select cluster: ")) - 1
        cluster = clusters[sel]
        # For OCP, you may need to use oc login or another method
        print("Please ensure you are logged in to the selected OCP cluster using 'oc login'.")
        return cluster["name"]
    else:
        print("Assuming self-managed or already configured cluster. No kubeconfig update performed.")
        return None


if __name__ == "__main__":
    # Step 1: Prompt and update kubeconfig
    cluster_name = select_and_update_kubeconfig()
    # Step 2: Run discovery as before
    kwargs = {}
    # Only pass kubeconfig/context if a cluster was selected and updated
    # (for self-managed, just use defaults)
    # This assumes the default kubeconfig is updated by the CLI tools
    # If you want to support custom kubeconfig/context, you can prompt for those as well
    # For now, just call with no args
    inventory = discover_kubernetes_inventory()
    print(json.dumps(inventory, indent=2))

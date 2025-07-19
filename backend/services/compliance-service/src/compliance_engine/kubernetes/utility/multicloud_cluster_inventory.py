"""
Multi-Cloud Kubernetes Cluster Inventory Script

Discovers all Kubernetes clusters in GCP (GKE), AWS (EKS), and Azure (AKS) using their respective CLIs.
Outputs a combined list for use with cluster, namespace, and resource discovery utilities.
"""

import subprocess
import json
import sys
from typing import List, Dict, Any


def list_gke_clusters(projects: List[str] = None) -> List[Dict[str, Any]]:
    """List all GKE clusters in the given GCP projects."""
    clusters = []
    try:
        # Get all projects if not provided
        if not projects:
            cmd = ["gcloud", "projects", "list", "--format=json"]
            output = subprocess.check_output(cmd)
            projects = [p["projectId"] for p in json.loads(output)]
        for project in projects:
            cmd = [
                "gcloud", "container", "clusters", "list",
                "--project", project,
                "--format=json"
            ]
            try:
                output = subprocess.check_output(cmd)
                gke_clusters = json.loads(output)
                for c in gke_clusters:
                    clusters.append({
                        "provider": "gcp",
                        "project": project,
                        "name": c["name"],
                        "location": c["location"],
                        "endpoint": c.get("endpoint"),
                        "status": c.get("status"),
                        "version": c.get("currentMasterVersion")
                    })
            except subprocess.CalledProcessError:
                continue
    except Exception as e:
        print(f"[GCP] Error: {e}")
    return clusters


def list_eks_clusters(regions: List[str] = None) -> List[Dict[str, Any]]:
    """List all EKS clusters in the given AWS regions."""
    clusters = []
    try:
        # Get all regions if not provided
        if not regions:
            cmd = ["aws", "ec2", "describe-regions", "--query", "Regions[].RegionName", "--output", "json"]
            output = subprocess.check_output(cmd)
            regions = json.loads(output)
        for region in regions:
            cmd = [
                "aws", "eks", "list-clusters",
                "--region", region,
                "--output", "json"
            ]
            try:
                output = subprocess.check_output(cmd)
                eks_clusters = json.loads(output)["clusters"]
                for name in eks_clusters:
                    # Get cluster details
                    desc_cmd = [
                        "aws", "eks", "describe-cluster",
                        "--region", region,
                        "--name", name,
                        "--output", "json"
                    ]
                    desc_out = subprocess.check_output(desc_cmd)
                    desc = json.loads(desc_out)["cluster"]
                    clusters.append({
                        "provider": "aws",
                        "region": region,
                        "name": name,
                        "endpoint": desc.get("endpoint"),
                        "status": desc.get("status"),
                        "version": desc.get("version")
                    })
            except subprocess.CalledProcessError:
                continue
    except Exception as e:
        print(f"[AWS] Error: {e}")
    return clusters


def list_aks_clusters() -> List[Dict[str, Any]]:
    """List all AKS clusters in the current Azure subscription."""
    clusters = []
    try:
        cmd = ["az", "aks", "list", "--query", "[]", "--output", "json"]
        output = subprocess.check_output(cmd)
        aks_clusters = json.loads(output)
        for c in aks_clusters:
            clusters.append({
                "provider": "azure",
                "resourceGroup": c["resourceGroup"],
                "name": c["name"],
                "location": c["location"],
                "endpoint": c.get("fqdn"),
                "status": c.get("provisioningState"),
                "version": c.get("kubernetesVersion")
            })
    except Exception as e:
        print(f"[Azure] Error: {e}")
    return clusters


def list_ocp_clusters() -> List[Dict[str, Any]]:
    """List all OpenShift clusters using ocm, rosa, and oc (for ACM) CLIs."""
    clusters = []
    # Try OCM CLI
    try:
        cmd = ["ocm", "list", "clusters", "--output", "json"]
        output = subprocess.check_output(cmd)
        ocm_clusters = json.loads(output)
        for c in ocm_clusters:
            clusters.append({
                "provider": "ocp",
                "source": "ocm",
                "name": c.get("name"),
                "id": c.get("id"),
                "api": c.get("api", {}).get("url"),
                "region": c.get("region", {}).get("id"),
                "status": c.get("status"),
                "version": c.get("openshift_version")
            })
    except Exception as e:
        print(f"[OCP/OCM] Error: {e}")
    # Try ROSA CLI
    try:
        cmd = ["rosa", "list", "clusters", "--output", "json"]
        output = subprocess.check_output(cmd)
        rosa_clusters = json.loads(output)
        for c in rosa_clusters:
            clusters.append({
                "provider": "ocp",
                "source": "rosa",
                "name": c.get("name"),
                "id": c.get("id"),
                "api": c.get("api", {}).get("url"),
                "region": c.get("region"),
                "status": c.get("state"),
                "version": c.get("version")
            })
    except Exception as e:
        print(f"[OCP/ROSA] Error: {e}")
    # Try ACM (oc get managedclusters)
    try:
        cmd = ["oc", "get", "managedclusters", "-A", "-o", "json"]
        output = subprocess.check_output(cmd)
        acm_clusters = json.loads(output)
        for item in acm_clusters.get("items", []):
            clusters.append({
                "provider": "ocp",
                "source": "acm",
                "name": item["metadata"]["name"],
                "api": item["spec"].get("hubAcceptsClient", None),
                "region": item["metadata"].get("labels", {}).get("cloud", ""),
                "status": item["status"].get("conditions", [{}])[-1].get("type", ""),
                "version": item["status"].get("version", {}).get("desired", "")
            })
    except Exception as e:
        print(f"[OCP/ACM] Error: {e}")
    return clusters


def main():
    print("\n=== Multi-Cloud Kubernetes Cluster Inventory ===\n")
    all_clusters = []
    
    print("[GCP] Discovering GKE clusters...")
    gke_clusters = list_gke_clusters()
    print(f"  Found {len(gke_clusters)} GKE clusters.")
    all_clusters.extend(gke_clusters)
    
    print("[AWS] Discovering EKS clusters...")
    eks_clusters = list_eks_clusters()
    print(f"  Found {len(eks_clusters)} EKS clusters.")
    all_clusters.extend(eks_clusters)
    
    print("[Azure] Discovering AKS clusters...")
    aks_clusters = list_aks_clusters()
    print(f"  Found {len(aks_clusters)} AKS clusters.")
    all_clusters.extend(aks_clusters)
    
    print("[OCP] Discovering OpenShift clusters...")
    ocp_clusters = list_ocp_clusters()
    print(f"  Found {len(ocp_clusters)} OCP clusters.")
    all_clusters.extend(ocp_clusters)
    
    print(f"\nTotal clusters found: {len(all_clusters)}\n")
    print("Provider,Name,Location/Region,Endpoint,Status,Version")
    for c in all_clusters:
        print(f"{c.get('provider')},{c.get('name')},{c.get('location', c.get('region', c.get('project', '')))},"
              f"{c.get('endpoint', c.get('api', '') )},{c.get('status')},{c.get('version')}")
    
    # Optionally, save to JSON/CSV for further processing
    with open("multicloud_clusters.json", "w") as f:
        json.dump(all_clusters, f, indent=2)
    print("\nCluster inventory saved to multicloud_clusters.json")

if __name__ == "__main__":
    main() 
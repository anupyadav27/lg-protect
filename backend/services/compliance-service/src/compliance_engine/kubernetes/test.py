#!/usr/bin/env python3
"""
Test script for dynamic loading of apiserver checks
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_dynamic_loading():
    """Test if the apiserver service can load checks dynamically."""
    
    try:
        # Try to import the kubernetes module first
        import kubernetes
        print(f"✅ kubernetes module available (version: {kubernetes.__version__})")
        
        # Now try to import our service
        from kubernetes_checks.apiserver.apiserver_service import KubernetesChecksAPIServer
        print("✅ KubernetesChecksAPIServer imported successfully!")
        
        # Create a mock provider (you'll need to replace this with actual k8s client)
        mock_provider = None
        
        # Initialize the service
        apiserver_service = KubernetesChecksAPIServer(mock_provider)
        
        # Check if checks were loaded
        available_checks = apiserver_service.get_available_checks()
        print(f"Available checks: {available_checks}")
        
        # Check if our specific check is loaded
        if "always pull images plugin" in available_checks:
            print("✅ apiserver_always_pull_images_plugin check loaded successfully!")
        else:
            print("❌ apiserver_always_pull_images_plugin check not found!")
            
    except ImportError as e:
        print(f"❌ Import error: {e}")
        print("Please install the required dependencies:")
        print("pip install -r requirements.txt")
    except Exception as e:
        print(f"❌ Error testing dynamic loading: {e}")

if __name__ == "__main__":
    test_dynamic_loading()
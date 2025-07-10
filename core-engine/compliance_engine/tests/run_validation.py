#!/usr/bin/env python3
"""
Compliance Engine Test Runner

Simple test runner for validating compliance engine components.
Run this script to verify all components are working correctly.
"""

import os
import sys

def run_validation():
    """Run the compliance engine validation."""
    print("🧪 Running Compliance Engine Validation...")
    print("=" * 50)
    
    # Change to the tests directory
    test_dir = os.path.dirname(os.path.abspath(__file__))
    test_file = os.path.join(test_dir, 'direct_component_test.py')
    
    if os.path.exists(test_file):
        # Import and run the test function directly
        sys.path.insert(0, test_dir)
        try:
            from direct_component_test import test_component_functionality
            return test_component_functionality()
        except ImportError as e:
            print(f"❌ Failed to import test module: {e}")
            return False
    else:
        print("❌ Test file not found!")
        return False

if __name__ == '__main__':
    success = run_validation()
    sys.exit(0 if success else 1)
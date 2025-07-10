#!/usr/bin/env python3
"""
Inventory Compliance Bridge Package

This package provides integration between AWS service inventory discovery 
and compliance validation using the existing ComplianceEngine architecture.

Main Components:
- ComplianceFunctionRegistry: Registry of all compliance functions
- InventoryComplianceIntegration: Main orchestrator
- Test Suite: Comprehensive testing framework
"""

from .compliance_function_registry import ComplianceFunctionRegistry
from .inventory_compliance_integration import (
    InventoryComplianceIntegration,
    run_from_inventory_file,
    run_from_inventory_data,
    run_with_defaults
)
from .main_runner import quick_run, run_compliance_for_service

__version__ = "1.0.0"
__author__ = "LG-Protect Team"

__all__ = [
    'ComplianceFunctionRegistry',
    'InventoryComplianceIntegration', 
    'run_from_inventory_file',
    'run_from_inventory_data',
    'run_with_defaults',
    'quick_run',
    'run_compliance_for_service'
]
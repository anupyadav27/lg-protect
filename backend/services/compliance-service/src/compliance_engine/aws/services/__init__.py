"""
Compliance Engine - AWS Services

Centralized imports and utilities for AWS compliance checks.
"""

import sys
import os
from pathlib import Path

# Add the parent directory to Python path for imports
current_dir = Path(__file__).parent
parent_dir = current_dir.parent
sys.path.append(str(parent_dir))

# Centralized imports
try:
    from base import BaseService, BaseCheck, ComplianceResult
    from utils.reports.reporting import create_compliance_report
except ImportError as e:
    print(f"Warning: Could not import base classes: {e}")

# Common imports that can be used across all services
__all__ = [
    'BaseService',
    'BaseCheck', 
    'ComplianceResult',
    'create_compliance_report'
]
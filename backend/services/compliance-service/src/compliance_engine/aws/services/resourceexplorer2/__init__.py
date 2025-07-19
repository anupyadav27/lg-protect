"""
AWS Resourceexplorer2 Service Module

Centralized imports for AWS Resourceexplorer2 compliance checks.
"""

# Import the service class
from .resourceexplorer2_service import ResourceExplorer2Service

# Import individual checks
from .resourceexplorer2_indexes_found.resourceexplorer2_indexes_found import resourceexplorer2_indexes_found

__all__ = [
    'ResourceExplorer2Service',
    'resourceexplorer2_indexes_found',
]

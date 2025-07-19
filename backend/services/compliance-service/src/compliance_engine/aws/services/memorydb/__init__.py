"""
AWS Memorydb Service Module

Centralized imports for AWS Memorydb compliance checks.
"""

# Import the service class
from .memorydb_service import MemoryDBService

# Import individual checks
from .memorydb_cluster_auto_minor_version_upgrades.memorydb_cluster_auto_minor_version_upgrades import memorydb_cluster_auto_minor_version_upgrades

__all__ = [
    'MemoryDBService',
    'memorydb_cluster_auto_minor_version_upgrades',
]

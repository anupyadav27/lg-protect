"""
AWS Documentdb Service Module

Centralized imports for AWS Documentdb compliance checks.
"""

# Import the service class
from .documentdb_service import DocumentDBService

# Import individual checks
from .documentdb_cluster_backup_enabled.documentdb_cluster_backup_enabled import documentdb_cluster_backup_enabled
from .documentdb_cluster_cloudwatch_log_export.documentdb_cluster_cloudwatch_log_export import documentdb_cluster_cloudwatch_log_export
from .documentdb_cluster_deletion_protection.documentdb_cluster_deletion_protection import documentdb_cluster_deletion_protection
from .documentdb_cluster_multi_az_enabled.documentdb_cluster_multi_az_enabled import documentdb_cluster_multi_az_enabled
from .documentdb_cluster_public_snapshot.documentdb_cluster_public_snapshot import documentdb_cluster_public_snapshot
from .documentdb_cluster_storage_encrypted.documentdb_cluster_storage_encrypted import documentdb_cluster_storage_encrypted

__all__ = [
    'DocumentDBService',
    'documentdb_cluster_backup_enabled',
    'documentdb_cluster_cloudwatch_log_export',
    'documentdb_cluster_deletion_protection',
    'documentdb_cluster_multi_az_enabled',
    'documentdb_cluster_public_snapshot',
    'documentdb_cluster_storage_encrypted',
]

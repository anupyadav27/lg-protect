"""
AWS Emr Service Module

Centralized imports for AWS Emr compliance checks.
"""

# Import the service class
from .emr_service import EMRService

# Import individual checks
from .emr_cluster_account_public_block_enabled.emr_cluster_account_public_block_enabled import emr_cluster_account_public_block_enabled
from .emr_cluster_master_nodes_no_public_ip.emr_cluster_master_nodes_no_public_ip import emr_cluster_master_nodes_no_public_ip
from .emr_cluster_publicly_accesible.emr_cluster_publicly_accesible import emr_cluster_publicly_accesible

__all__ = [
    'EMRService',
    'emr_cluster_account_public_block_enabled',
    'emr_cluster_master_nodes_no_public_ip',
    'emr_cluster_publicly_accesible',
]

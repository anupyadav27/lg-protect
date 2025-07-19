"""
AWS Storagegateway Service Module

Centralized imports for AWS Storagegateway compliance checks.
"""

# Import the service class
from .storagegateway_service import StorageGatewayService

# Import individual checks
from .storagegateway_fileshare_encryption_enabled.storagegateway_fileshare_encryption_enabled import storagegateway_fileshare_encryption_enabled
from .storagegateway_gateway_fault_tolerant.storagegateway_gateway_fault_tolerant import storagegateway_gateway_fault_tolerant

__all__ = [
    'StorageGatewayService',
    'storagegateway_fileshare_encryption_enabled',
    'storagegateway_gateway_fault_tolerant',
]

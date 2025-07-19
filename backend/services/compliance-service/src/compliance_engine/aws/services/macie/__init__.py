"""
AWS Macie Service Module

Centralized imports for AWS Macie compliance checks.
"""

# Import the service class
from .macie_service import MacieService

# Import individual checks
from .macie_automated_sensitive_data_discovery_enabled.macie_automated_sensitive_data_discovery_enabled import macie_automated_sensitive_data_discovery_enabled
from .macie_is_enabled.macie_is_enabled import macie_is_enabled

__all__ = [
    'MacieService',
    'macie_automated_sensitive_data_discovery_enabled',
    'macie_is_enabled',
]

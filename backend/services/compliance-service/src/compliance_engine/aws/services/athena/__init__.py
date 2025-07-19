"""
Athena Service Module

Centralized imports for Athena compliance checks.
"""

# Import the service class
from .athena_service import AthenaService

# Import individual checks
from .athena_workgroup_encryption.athena_workgroup_encryption import athena_workgroup_encryption
from .athena_workgroup_enforce_configuration.athena_workgroup_enforce_configuration import athena_workgroup_enforce_configuration
from .athena_workgroup_logging_enabled.athena_workgroup_logging_enabled import athena_workgroup_logging_enabled

__all__ = [
    'AthenaService',
    'athena_workgroup_encryption',
    'athena_workgroup_enforce_configuration',
    'athena_workgroup_logging_enabled'
]

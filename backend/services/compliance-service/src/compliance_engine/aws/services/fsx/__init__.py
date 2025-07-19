"""
AWS Fsx Service Module

Centralized imports for AWS Fsx compliance checks.
"""

# Import the service class
from .fsx_service import FSxService

# Import individual checks
from .fsx_file_system_copy_tags_to_backups_enabled.fsx_file_system_copy_tags_to_backups_enabled import fsx_file_system_copy_tags_to_backups_enabled
from .fsx_file_system_copy_tags_to_volumes_enabled.fsx_file_system_copy_tags_to_volumes_enabled import fsx_file_system_copy_tags_to_volumes_enabled
from .fsx_windows_file_system_multi_az_enabled.fsx_windows_file_system_multi_az_enabled import fsx_windows_file_system_multi_az_enabled

__all__ = [
    'FSxService',
    'fsx_file_system_copy_tags_to_backups_enabled',
    'fsx_file_system_copy_tags_to_volumes_enabled',
    'fsx_windows_file_system_multi_az_enabled',
]

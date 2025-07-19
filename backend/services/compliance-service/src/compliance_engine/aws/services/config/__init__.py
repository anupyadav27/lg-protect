"""
AWS Config Service Module

Centralized imports for AWS Config compliance checks.
"""

# Import the service class
from .config_service import ConfigService

# Import individual checks
from .config_recorder_all_regions_enabled.config_recorder_all_regions_enabled import config_recorder_all_regions_enabled
from .config_recorder_using_aws_service_role.config_recorder_using_aws_service_role import config_recorder_using_aws_service_role

__all__ = [
    'ConfigService',
    'config_recorder_all_regions_enabled',
    'config_recorder_using_aws_service_role',
]

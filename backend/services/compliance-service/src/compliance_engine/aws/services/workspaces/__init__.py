"""
AWS Workspaces Service Module

Centralized imports for AWS Workspaces compliance checks.
"""

# Import the service class
from .workspaces_service import WorkSpacesService

# Import individual checks
from .workspaces_volume_encryption_enabled.workspaces_volume_encryption_enabled import workspaces_volume_encryption_enabled
from .workspaces_vpc_2private_1public_subnets_nat.workspaces_vpc_2private_1public_subnets_nat import workspaces_vpc_2private_1public_subnets_nat

__all__ = [
    'WorkSpacesService',
    'workspaces_volume_encryption_enabled',
    'workspaces_vpc_2private_1public_subnets_nat',
]

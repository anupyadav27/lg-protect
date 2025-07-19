"""
AWS Dlm Service Module

Centralized imports for AWS Dlm compliance checks.
"""

# Import the service class
from .dlm_service import DLMService

# Import individual checks
from .dlm_ebs_snapshot_lifecycle_policy_exists.dlm_ebs_snapshot_lifecycle_policy_exists import dlm_ebs_snapshot_lifecycle_policy_exists

__all__ = [
    'DLMService',
    'dlm_ebs_snapshot_lifecycle_policy_exists',
]

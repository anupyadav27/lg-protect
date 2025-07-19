"""
AWS Fms Service Module

Centralized imports for AWS Fms compliance checks.
"""

# Import the service class
from .fms_service import FMSService

# Import individual checks
from .fms_policy_compliant.fms_policy_compliant import fms_policy_compliant

__all__ = [
    'FMSService',
    'fms_policy_compliant',
]

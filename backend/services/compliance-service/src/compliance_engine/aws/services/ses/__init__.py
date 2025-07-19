"""
AWS Ses Service Module

Centralized imports for AWS Ses compliance checks.
"""

# Import the service class
from .ses_service import SESService

# Import individual checks
from .ses_identity_not_publicly_accessible.ses_identity_not_publicly_accessible import ses_identity_not_publicly_accessible

__all__ = [
    'SESService',
    'ses_identity_not_publicly_accessible',
]

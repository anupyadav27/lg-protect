"""
AWS Ssm Service Module

Centralized imports for AWS Ssm compliance checks.
"""

# Import the service class
from .ssm_service import SSMService

# Import individual checks
from .ssm_document_secrets.ssm_document_secrets import ssm_document_secrets
from .ssm_documents_set_as_public.ssm_documents_set_as_public import ssm_documents_set_as_public
from .ssm_managed_compliant_patching.ssm_managed_compliant_patching import ssm_managed_compliant_patching

__all__ = [
    'SSMService',
    'ssm_document_secrets',
    'ssm_documents_set_as_public',
    'ssm_managed_compliant_patching',
]

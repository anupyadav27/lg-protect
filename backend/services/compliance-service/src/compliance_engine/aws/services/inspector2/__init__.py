"""
AWS Inspector2 Service Module

Centralized imports for AWS Inspector2 compliance checks.
"""

# Import the service class
from .inspector2_service import Inspector2Service

# Import individual checks
from .inspector2_active_findings_exist.inspector2_active_findings_exist import inspector2_active_findings_exist
from .inspector2_is_enabled.inspector2_is_enabled import inspector2_is_enabled

__all__ = [
    'Inspector2Service',
    'inspector2_active_findings_exist',
    'inspector2_is_enabled',
]

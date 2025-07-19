"""
AWS Ecr Service Module

Centralized imports for AWS Ecr compliance checks.
"""

# Import the service class
from .ecr_service import ECRService

# Import individual checks
from .ecr_registry_scan_images_on_push_enabled.ecr_registry_scan_images_on_push_enabled import ecr_registry_scan_images_on_push_enabled
from .ecr_repositories_lifecycle_policy_enabled.ecr_repositories_lifecycle_policy_enabled import ecr_repositories_lifecycle_policy_enabled
from .ecr_repositories_not_publicly_accessible.ecr_repositories_not_publicly_accessible import ecr_repositories_not_publicly_accessible
from .ecr_repositories_scan_images_on_push_enabled.ecr_repositories_scan_images_on_push_enabled import ecr_repositories_scan_images_on_push_enabled
from .ecr_repositories_scan_vulnerabilities_in_latest_image.ecr_repositories_scan_vulnerabilities_in_latest_image import ecr_repositories_scan_vulnerabilities_in_latest_image
from .ecr_repositories_tag_immutability.ecr_repositories_tag_immutability import ecr_repositories_tag_immutability

__all__ = [
    'ECRService',
    'ecr_registry_scan_images_on_push_enabled',
    'ecr_repositories_lifecycle_policy_enabled',
    'ecr_repositories_not_publicly_accessible',
    'ecr_repositories_scan_images_on_push_enabled',
    'ecr_repositories_scan_vulnerabilities_in_latest_image',
    'ecr_repositories_tag_immutability',
]

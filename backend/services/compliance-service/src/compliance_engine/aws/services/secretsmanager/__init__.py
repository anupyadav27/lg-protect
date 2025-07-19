"""
AWS Secretsmanager Service Module

Centralized imports for AWS Secretsmanager compliance checks.
"""

# Import the service class
from .secretsmanager_service import SecretsManagerService

# Import individual checks
from .secretsmanager_automatic_rotation_enabled.secretsmanager_automatic_rotation_enabled import secretsmanager_automatic_rotation_enabled
from .secretsmanager_not_publicly_accessible.secretsmanager_not_publicly_accessible import secretsmanager_not_publicly_accessible
from .secretsmanager_secret_rotated_periodically.secretsmanager_secret_rotated_periodically import secretsmanager_secret_rotated_periodically
from .secretsmanager_secret_unused.secretsmanager_secret_unused import secretsmanager_secret_unused

__all__ = [
    'SecretsManagerService',
    'secretsmanager_automatic_rotation_enabled',
    'secretsmanager_not_publicly_accessible',
    'secretsmanager_secret_rotated_periodically',
    'secretsmanager_secret_unused',
]

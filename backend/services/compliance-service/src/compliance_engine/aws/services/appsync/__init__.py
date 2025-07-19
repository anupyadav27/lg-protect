"""
AppSync Service Module

Centralized imports for AppSync compliance checks.
"""

# Import the service class
from .appsync_service import AppSyncService

# Import individual checks
from .appsync_field_level_logging_enabled.appsync_field_level_logging_enabled import appsync_field_level_logging_enabled
from .appsync_graphql_api_no_api_key_authentication.appsync_graphql_api_no_api_key_authentication import appsync_graphql_api_no_api_key_authentication

__all__ = [
    'AppSyncService',
    'appsync_field_level_logging_enabled',
    'appsync_graphql_api_no_api_key_authentication'
]

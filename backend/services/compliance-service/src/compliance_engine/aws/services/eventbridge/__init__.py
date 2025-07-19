"""
AWS Eventbridge Service Module

Centralized imports for AWS Eventbridge compliance checks.
"""

# Import the service class
from .eventbridge_service import EventBridgeService

# Import individual checks
from .eventbridge_bus_cross_account_access.eventbridge_bus_cross_account_access import eventbridge_bus_cross_account_access
from .eventbridge_bus_exposed.eventbridge_bus_exposed import eventbridge_bus_exposed
from .eventbridge_global_endpoint_event_replication_enabled.eventbridge_global_endpoint_event_replication_enabled import eventbridge_global_endpoint_event_replication_enabled
from .eventbridge_schema_registry_cross_account_access.eventbridge_schema_registry_cross_account_access import eventbridge_schema_registry_cross_account_access

__all__ = [
    'EventBridgeService',
    'eventbridge_bus_cross_account_access',
    'eventbridge_bus_exposed',
    'eventbridge_global_endpoint_event_replication_enabled',
    'eventbridge_schema_registry_cross_account_access',
]

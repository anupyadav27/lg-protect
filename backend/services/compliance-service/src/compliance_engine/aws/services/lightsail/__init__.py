"""
AWS Lightsail Service Module

Centralized imports for AWS Lightsail compliance checks.
"""

# Import the service class
from .lightsail_service import LightsailService

# Import individual checks
from .lightsail_database_public.lightsail_database_public import lightsail_database_public
from .lightsail_instance_automated_snapshots.lightsail_instance_automated_snapshots import lightsail_instance_automated_snapshots
from .lightsail_instance_public.lightsail_instance_public import lightsail_instance_public
from .lightsail_static_ip_unused.lightsail_static_ip_unused import lightsail_static_ip_unused

__all__ = [
    'LightsailService',
    'lightsail_database_public',
    'lightsail_instance_automated_snapshots',
    'lightsail_instance_public',
    'lightsail_static_ip_unused',
]

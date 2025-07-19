"""
AWS Vpc Service Module

Centralized imports for AWS Vpc compliance checks.
"""

# Import the service class
from .vpc_service import VPCService

# Import individual checks
from .vpc_different_regions.vpc_different_regions import vpc_different_regions
from .vpc_endpoint_connections_trust_boundaries.vpc_endpoint_connections_trust_boundaries import vpc_endpoint_connections_trust_boundaries
from .vpc_endpoint_for_ec2_enabled.vpc_endpoint_for_ec2_enabled import vpc_endpoint_for_ec2_enabled
from .vpc_endpoint_multi_az_enabled.vpc_endpoint_multi_az_enabled import vpc_endpoint_multi_az_enabled
from .vpc_endpoint_services_allowed_principals_trust_boundaries.vpc_endpoint_services_allowed_principals_trust_boundaries import vpc_endpoint_services_allowed_principals_trust_boundaries
from .vpc_flow_logs_enabled.vpc_flow_logs_enabled import vpc_flow_logs_enabled
from .vpc_peering_routing_tables_with_least_privilege.vpc_peering_routing_tables_with_least_privilege import vpc_peering_routing_tables_with_least_privilege
from .vpc_subnet_different_az.vpc_subnet_different_az import vpc_subnet_different_az
from .vpc_subnet_no_public_ip_by_default.vpc_subnet_no_public_ip_by_default import vpc_subnet_no_public_ip_by_default
from .vpc_subnet_separate_private_public.vpc_subnet_separate_private_public import vpc_subnet_separate_private_public
from .vpc_vpn_connection_tunnels_up.vpc_vpn_connection_tunnels_up import vpc_vpn_connection_tunnels_up

__all__ = [
    'VPCService',
    'vpc_different_regions',
    'vpc_endpoint_connections_trust_boundaries',
    'vpc_endpoint_for_ec2_enabled',
    'vpc_endpoint_multi_az_enabled',
    'vpc_endpoint_services_allowed_principals_trust_boundaries',
    'vpc_flow_logs_enabled',
    'vpc_peering_routing_tables_with_least_privilege',
    'vpc_subnet_different_az',
    'vpc_subnet_no_public_ip_by_default',
    'vpc_subnet_separate_private_public',
    'vpc_vpn_connection_tunnels_up',
]

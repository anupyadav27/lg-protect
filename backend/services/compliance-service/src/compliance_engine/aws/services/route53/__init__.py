"""
AWS Route53 Service Module

Centralized imports for AWS Route53 compliance checks.
"""

# Import the service class
from .route53_service import Route53Service

# Import individual checks
from .route53_dangling_ip_subdomain_takeover.route53_dangling_ip_subdomain_takeover import route53_dangling_ip_subdomain_takeover
from .route53_domains_privacy_protection_enabled.route53_domains_privacy_protection_enabled import route53_domains_privacy_protection_enabled
from .route53_domains_transferlock_enabled.route53_domains_transferlock_enabled import route53_domains_transferlock_enabled
from .route53_public_hosted_zones_cloudwatch_logging_enabled.route53_public_hosted_zones_cloudwatch_logging_enabled import route53_public_hosted_zones_cloudwatch_logging_enabled

__all__ = [
    'Route53Service',
    'route53_dangling_ip_subdomain_takeover',
    'route53_domains_privacy_protection_enabled',
    'route53_domains_transferlock_enabled',
    'route53_public_hosted_zones_cloudwatch_logging_enabled',
]

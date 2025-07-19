"""
AWS Wafv2 Service Module

Centralized imports for AWS Wafv2 compliance checks.
"""

# Import the service class
from .wafv2_service import WAFV2Service

# Import individual checks
from .wafv2_webacl_logging_enabled.wafv2_webacl_logging_enabled import wafv2_webacl_logging_enabled
from .wafv2_webacl_rule_logging_enabled.wafv2_webacl_rule_logging_enabled import wafv2_webacl_rule_logging_enabled
from .wafv2_webacl_with_rules.wafv2_webacl_with_rules import wafv2_webacl_with_rules

__all__ = [
    'WAFV2Service',
    'wafv2_webacl_logging_enabled',
    'wafv2_webacl_rule_logging_enabled',
    'wafv2_webacl_with_rules',
]

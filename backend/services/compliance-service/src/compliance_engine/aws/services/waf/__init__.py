"""
AWS Waf Service Module

Centralized imports for AWS Waf compliance checks.
"""

# Import the service class
from .waf_service import WAFService

# Import individual checks
from .waf_global_rule_with_conditions.waf_global_rule_with_conditions import waf_global_rule_with_conditions
from .waf_global_rulegroup_not_empty.waf_global_rulegroup_not_empty import waf_global_rulegroup_not_empty
from .waf_global_webacl_logging_enabled.waf_global_webacl_logging_enabled import waf_global_webacl_logging_enabled
from .waf_global_webacl_with_rules.waf_global_webacl_with_rules import waf_global_webacl_with_rules
from .waf_regional_rule_with_conditions.waf_regional_rule_with_conditions import waf_regional_rule_with_conditions
from .waf_regional_rulegroup_not_empty.waf_regional_rulegroup_not_empty import waf_regional_rulegroup_not_empty
from .waf_regional_webacl_with_rules.waf_regional_webacl_with_rules import waf_regional_webacl_with_rules

__all__ = [
    'WAFService',
    'waf_global_rule_with_conditions',
    'waf_global_rulegroup_not_empty',
    'waf_global_webacl_logging_enabled',
    'waf_global_webacl_with_rules',
    'waf_regional_rule_with_conditions',
    'waf_regional_rulegroup_not_empty',
    'waf_regional_webacl_with_rules',
]

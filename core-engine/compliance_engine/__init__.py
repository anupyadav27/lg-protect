"""
Compliance Engine Package

Main package for the compliance engine modules.
"""

from .compliance_engine import ComplianceEngine
from .aws_session_manager import (
    create_aws_session, 
    create_enhanced_aws_client,
    get_aws_profiles,
    extract_service_name,
    get_regions_for_service,
    GLOBAL_SERVICES
)
from .error_handler import (
    EnhancedErrorLogger,
    handle_enhanced_client_error,
    handle_client_error,
    update_global_stats,
    global_stats
)
from .config_utils import (
    setup_logging,
    load_service_regions,
    initialize_compliance_results,
    determine_overall_status,
    setup_command_line_interface,
    save_results,
    exit_with_status
)
from .account_manager import (
    EnterpriseAccountManager,
    get_account_manager_from_profiles
)

__all__ = [
    'ComplianceEngine',
    'create_aws_session',
    'create_enhanced_aws_client', 
    'get_aws_profiles',
    'extract_service_name',
    'get_regions_for_service',
    'GLOBAL_SERVICES',
    'EnhancedErrorLogger',
    'handle_enhanced_client_error',
    'handle_client_error',
    'update_global_stats',
    'global_stats',
    'setup_logging',
    'load_service_regions',
    'initialize_compliance_results',
    'determine_overall_status',
    'setup_command_line_interface',
    'save_results',
    'exit_with_status',
    'EnterpriseAccountManager',
    'get_account_manager_from_profiles'
]
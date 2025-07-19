"""
Account Service Module

Centralized imports for Account compliance checks.
"""

# Import the service class
from .account_service import AccountService

# Import individual checks
from .account_maintain_current_contact_details.account_maintain_current_contact_details import account_maintain_current_contact_details
from .account_security_contact_information_is_registered.account_security_contact_information_is_registered import account_security_contact_information_is_registered
from .account_security_questions_are_registered_in_the_aws_account.account_security_questions_are_registered_in_the_aws_account import account_security_questions_are_registered_in_the_aws_account

__all__ = [
    'AccountService',
    'account_maintain_current_contact_details',
    'account_security_contact_information_is_registered',
    'account_security_questions_are_registered_in_the_aws_account'
]

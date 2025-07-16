"""
Account Security Questions Are Registered Compliance Check

Checks if AWS account has security questions registered.
"""

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', 'utils'))
from utils.reporting import (
    BaseCheck, CheckReport, CheckMetadata, CheckStatus, 
    Severity, ComplianceStandard
)

from ..account_client import get_account_client


class account_security_questions_are_registered_in_the_aws_account(BaseCheck):
    """Check if AWS account has security questions registered"""
    
    def _get_metadata(self) -> CheckMetadata:
        """Get check metadata"""
        return CheckMetadata(
            check_id="account_security_questions_are_registered_in_the_aws_account",
            check_name="Account Security Questions Are Registered",
            description="Ensure AWS account has security questions registered for account recovery",
            severity=Severity.MEDIUM,
            compliance_standard=ComplianceStandard.AWS_FOUNDATIONAL_SECURITY_BEST_PRACTICES,
            category="Account Management",
            tags=["account", "security", "questions", "recovery"],
            remediation="Login to the AWS Console as root. Choose your account name on the top right of the window -> My Account -> Configure Security Challenge Questions.",
            references=[
                "https://docs.aws.amazon.com/accounts/latest/reference/manage-acct-update-contact.html",
                "https://aws.amazon.com/premiumsupport/knowledge-center/update-account-contact-information/"
            ]
        )
    
    def execute(self) -> list[CheckReport]:
        """Execute the compliance check"""
        findings = []
        
        # Get account client
        session = get_account_client()
        
        # Get account information
        account_info = self._get_account_info(session)
        
        # Check security questions
        report = self._check_security_questions(account_info)
        findings.append(report)
        
        return findings
    
    def _get_account_info(self, session):
        """Get account information"""
        try:
            # Get account identity
            sts_client = session.client('sts')
            account_identity = sts_client.get_caller_identity()
            
            # Security questions cannot be checked via API - manual verification required
            return {
                'account_id': account_identity['Account'],
                'account_arn': account_identity['Arn'],
                'security_questions': None  # Cannot be determined via API
            }
            
        except Exception as e:
            return {
                'account_id': 'unknown',
                'account_arn': 'unknown',
                'security_questions': None
            }
    
    def _check_security_questions(self, account_info) -> CheckReport:
        """Check if account has security questions registered"""
        
        # Security questions cannot be verified via API
        # This always requires manual verification
        status = CheckStatus.MANUAL
        status_extended = (
            f"AWS Account {account_info['account_id']} security questions require manual verification. "
            f"Login to the AWS Console as root. Choose your account name on the top right of the window -> "
            f"My Account -> Configure Security Challenge Questions."
        )
        
        # Create report for this account
        report = CheckReport(
            status=status,
            status_extended=status_extended,
            resource=account_info,
            metadata=self.metadata,
            region="global",  # Account-level checks are global
            evidence={
                "account_id": account_info['account_id'],
                "account_arn": account_info['account_arn'],
                "security_questions_verification": "manual_required"
            }
        )
        
        return report

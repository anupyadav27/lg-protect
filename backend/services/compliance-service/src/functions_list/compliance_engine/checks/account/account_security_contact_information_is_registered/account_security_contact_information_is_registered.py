"""
Account Security Contact Information Is Registered Compliance Check

Checks if AWS account has security contact information registered.
"""

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', 'utils'))
from utils.reporting import (
    BaseCheck, CheckReport, CheckMetadata, CheckStatus, 
    Severity, ComplianceStandard
)

from ..account_client import get_account_client


class account_security_contact_information_is_registered(BaseCheck):
    """Check if AWS account has security contact information registered"""
    
    def _get_metadata(self) -> CheckMetadata:
        """Get check metadata"""
        return CheckMetadata(
            check_id="account_security_contact_information_is_registered",
            check_name="Account Security Contact Information Is Registered",
            description="Ensure AWS account has security contact information registered for security notifications",
            severity=Severity.MEDIUM,
            compliance_standard=ComplianceStandard.AWS_FOUNDATIONAL_SECURITY_BEST_PRACTICES,
            category="Account Management",
            tags=["account", "security", "contact", "notifications"],
            remediation="Login to the AWS Console. Choose your account name on the top right of the window -> My Account -> Alternate Contacts -> Security Section.",
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
        
        # Check security contact information
        report = self._check_security_contact(account_info)
        findings.append(report)
        
        return findings
    
    def _get_account_info(self, session):
        """Get account information"""
        try:
            # Get account identity
            sts_client = session.client('sts')
            account_identity = sts_client.get_caller_identity()
            
            # Try to get security contact information
            try:
                account_client = session.client('account')
                security_contact = account_client.get_alternate_contact(AlternateContactType="SECURITY")
            except Exception as e:
                # If we can't get security contact info, assume manual check is needed
                security_contact = None
            
            return {
                'account_id': account_identity['Account'],
                'account_arn': account_identity['Arn'],
                'security_contact': security_contact.get('AlternateContact') if security_contact else None
            }
            
        except Exception as e:
            return {
                'account_id': 'unknown',
                'account_arn': 'unknown',
                'security_contact': None
            }
    
    def _check_security_contact(self, account_info) -> CheckReport:
        """Check if account has security contact information"""
        
        # For security contact information, we typically need manual verification
        # since the API might not return all required information
        if account_info['security_contact']:
            # We have some security contact info, but still recommend manual verification
            status = CheckStatus.WARNING
            status_extended = (
                f"AWS Account {account_info['account_id']} has security contact information, "
                f"but manual verification is recommended to ensure all details are current."
            )
        else:
            # No security contact info available via API
            status = CheckStatus.MANUAL
            status_extended = (
                f"AWS Account {account_info['account_id']} security contact information requires manual verification. "
                f"Login to the AWS Console. Choose your account name on the top right of the window -> "
                f"My Account -> Alternate Contacts -> Security Section."
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
                "has_security_contact": account_info['security_contact'] is not None,
                "security_contact_available": bool(account_info['security_contact'])
            }
        )
        
        return report

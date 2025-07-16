"""
Account Maintain Current Contact Details Compliance Check

Checks if AWS account maintains current contact details.
"""

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', 'utils'))
from utils.reporting import (
    BaseCheck, CheckReport, CheckMetadata, CheckStatus, 
    Severity, ComplianceStandard
)

from ..account_client import get_account_client


class account_maintain_current_contact_details(BaseCheck):
    """Check if AWS account maintains current contact details"""
    
    def _get_metadata(self) -> CheckMetadata:
        """Get check metadata"""
        return CheckMetadata(
            check_id="account_maintain_current_contact_details",
            check_name="Account Maintain Current Contact Details",
            description="Ensure AWS account maintains current contact details for billing and security notifications",
            severity=Severity.MEDIUM,
            compliance_standard=ComplianceStandard.AWS_FOUNDATIONAL_SECURITY_BEST_PRACTICES,
            category="Account Management",
            tags=["account", "contact", "billing", "security", "notifications"],
            remediation="Login to the AWS Console. Choose your account name on the top right of the window -> My Account -> Contact Information.",
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
        
        # Check account contact details
        report = self._check_contact_details(account_info)
        findings.append(report)
        
        return findings
    
    def _get_account_info(self, session):
        """Get account information"""
        try:
            # Get account identity
            sts_client = session.client('sts')
            account_identity = sts_client.get_caller_identity()
            
            # Try to get contact information
            try:
                account_client = session.client('account')
                contact_info = account_client.get_contact_information()
            except Exception as e:
                # If we can't get contact info, assume manual check is needed
                contact_info = None
            
            return {
                'account_id': account_identity['Account'],
                'account_arn': account_identity['Arn'],
                'contact_info': contact_info.get('ContactInformation') if contact_info else None
            }
            
        except Exception as e:
            return {
                'account_id': 'unknown',
                'account_arn': 'unknown',
                'contact_info': None
            }
    
    def _check_contact_details(self, account_info) -> CheckReport:
        """Check if account has current contact details"""
        
        # For account contact details, we typically need manual verification
        # since the API might not return all required information
        if account_info['contact_info']:
            # We have some contact info, but still recommend manual verification
            status = CheckStatus.WARNING
            status_extended = (
                f"AWS Account {account_info['account_id']} has contact information, "
                f"but manual verification is recommended to ensure all details are current."
            )
        else:
            # No contact info available via API
            status = CheckStatus.MANUAL
            status_extended = (
                f"AWS Account {account_info['account_id']} contact details require manual verification. "
                f"Login to the AWS Console. Choose your account name on the top right of the window -> "
                f"My Account -> Contact Information."
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
                "has_contact_info": account_info['contact_info'] is not None,
                "contact_info_available": bool(account_info['contact_info'])
            }
        )
        
        return report

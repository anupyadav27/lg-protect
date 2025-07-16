"""
Account Maintain Different Contact Details Compliance Check

Checks if AWS account maintains different contact details for security, billing, and operations.
"""

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', 'utils'))
from utils.reporting import (
    BaseCheck, CheckReport, CheckMetadata, CheckStatus, 
    Severity, ComplianceStandard
)

from ..account_client import get_account_client


class account_maintain_different_contact_details_to_security_billing_and_operations(BaseCheck):
    """Check if AWS account maintains different contact details for security, billing, and operations"""
    
    def _get_metadata(self) -> CheckMetadata:
        """Get check metadata"""
        return CheckMetadata(
            check_id="account_maintain_different_contact_details_to_security_billing_and_operations",
            check_name="Account Maintain Different Contact Details",
            description="Ensure AWS account maintains different contact details for security, billing, and operations",
            severity=Severity.MEDIUM,
            compliance_standard=ComplianceStandard.AWS_FOUNDATIONAL_SECURITY_BEST_PRACTICES,
            category="Account Management",
            tags=["account", "contact", "security", "billing", "operations"],
            remediation="Login to the AWS Console. Choose your account name on the top right of the window -> My Account -> Alternate Contacts -> Configure different contacts for Security, Billing, and Operations.",
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
        
        # Check different contact details
        report = self._check_different_contacts(account_info)
        findings.append(report)
        
        return findings
    
    def _get_account_info(self, session):
        """Get account information"""
        try:
            # Get account identity
            sts_client = session.client('sts')
            account_identity = sts_client.get_caller_identity()
            
            # Try to get different contact information
            try:
                account_client = session.client('account')
                
                # Get primary contact
                primary_contact = account_client.get_contact_information()
                
                # Get alternate contacts
                try:
                    security_contact = account_client.get_alternate_contact(AlternateContactType="SECURITY")
                except Exception:
                    security_contact = None
                
                try:
                    billing_contact = account_client.get_alternate_contact(AlternateContactType="BILLING")
                except Exception:
                    billing_contact = None
                
                try:
                    operations_contact = account_client.get_alternate_contact(AlternateContactType="OPERATIONS")
                except Exception:
                    operations_contact = None
                
                contacts = {
                    'primary': primary_contact.get('ContactInformation') if primary_contact else None,
                    'security': security_contact.get('AlternateContact') if security_contact else None,
                    'billing': billing_contact.get('AlternateContact') if billing_contact else None,
                    'operations': operations_contact.get('AlternateContact') if operations_contact else None
                }
                
            except Exception as e:
                # If we can't get contact info, assume manual check is needed
                contacts = None
            
            return {
                'account_id': account_identity['Account'],
                'account_arn': account_identity['Arn'],
                'contacts': contacts
            }
            
        except Exception as e:
            return {
                'account_id': 'unknown',
                'account_arn': 'unknown',
                'contacts': None
            }
    
    def _check_different_contacts(self, account_info) -> CheckReport:
        """Check if account has different contact details"""
        
        if not account_info['contacts']:
            # No contact info available via API
            status = CheckStatus.MANUAL
            status_extended = (
                f"AWS Account {account_info['account_id']} contact details require manual verification. "
                f"Login to the AWS Console. Choose your account name on the top right of the window -> "
                f"My Account -> Alternate Contacts -> Configure different contacts for Security, Billing, and Operations."
            )
        else:
            contacts = account_info['contacts']
            
            # Check if we have different contacts
            contact_emails = set()
            contact_phones = set()
            contact_names = set()
            
            for contact_type, contact in contacts.items():
                if contact:
                    if contact.get('EmailAddress'):
                        contact_emails.add(contact['EmailAddress'])
                    if contact.get('PhoneNumber'):
                        contact_phones.add(contact['PhoneNumber'])
                    if contact.get('Name') or contact.get('FullName'):
                        contact_names.add(contact.get('Name') or contact.get('FullName'))
            
            # Check if we have different contacts
            if len(contact_emails) >= 3 and len(contact_phones) >= 3 and len(contact_names) >= 3:
                status = CheckStatus.WARNING
                status_extended = (
                    f"AWS Account {account_info['account_id']} appears to have different contact details, "
                    f"but manual verification is recommended to ensure all details are current and properly configured."
                )
            else:
                status = CheckStatus.MANUAL
                status_extended = (
                    f"AWS Account {account_info['account_id']} may not have different contact details for all types. "
                    f"Manual verification required. Login to the AWS Console. Choose your account name on the top right of the window -> "
                    f"My Account -> Alternate Contacts -> Configure different contacts for Security, Billing, and Operations."
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
                "has_contacts": account_info['contacts'] is not None,
                "contact_types_available": list(account_info['contacts'].keys()) if account_info['contacts'] else []
            }
        )
        
        return report

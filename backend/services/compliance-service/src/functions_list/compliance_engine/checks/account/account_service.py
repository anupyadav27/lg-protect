"""
Account Service

Service abstraction for account compliance checks.
"""

from datetime import datetime
from typing import Optional, Dict, List
from pydantic import BaseModel
import boto3
import logging

logger = logging.getLogger(__name__)


class AccountInfo(BaseModel):
    """Account information model"""
    account_id: str
    account_arn: str
    account_name: Optional[str] = None
    contact_info: Optional[Dict] = None
    security_questions: Optional[bool] = None
    billing_contact: Optional[Dict] = None
    operations_contact: Optional[Dict] = None
    security_contact: Optional[Dict] = None
    
    @property
    def has_current_contact_details(self) -> bool:
        """Check if account has current contact details"""
        return self.contact_info is not None and len(self.contact_info) > 0
    
    @property
    def has_security_contact(self) -> bool:
        """Check if account has security contact information"""
        return self.security_contact is not None and len(self.security_contact) > 0
    
    @property
    def has_security_questions(self) -> bool:
        """Check if account has security questions registered"""
        return self.security_questions is True
    
    @property
    def has_different_contacts(self) -> bool:
        """Check if account has different contacts for security, billing, and operations"""
        return (
            self.security_contact is not None and
            self.billing_contact is not None and
            self.operations_contact is not None and
            self.security_contact != self.billing_contact and
            self.security_contact != self.operations_contact and
            self.billing_contact != self.operations_contact
        )


class AccountService:
    """Account service that collects account information"""
    
    def __init__(self, boto3_session: boto3.Session, regions: Optional[List[str]] = None):
        self.session = boto3_session
        self.account_info = None
        self._load_account_info()
    
    def _load_account_info(self):
        """Load account information from AWS"""
        try:
            # Get account information
            sts_client = self.session.client('sts')
            account_identity = sts_client.get_caller_identity()
            
            # Get account contact information
            account_client = self.session.client('account')
            
            try:
                contact_info = account_client.get_contact_information()
            except Exception as e:
                logger.warning(f"Could not get contact information: {e}")
                contact_info = None
            
            # Create account info object
            self.account_info = AccountInfo(
                account_id=account_identity['Account'],
                account_arn=account_identity['Arn'],
                contact_info=contact_info.get('ContactInformation') if contact_info else None,
                # Note: Security questions and detailed contact info would require
                # additional API calls or manual verification
                security_questions=None,  # Would need manual verification
                billing_contact=None,     # Would need additional API calls
                operations_contact=None,  # Would need additional API calls
                security_contact=None     # Would need additional API calls
            )
            
            logger.info(f"Loaded account information for account: {self.account_info.account_id}")
                    
        except Exception as error:
            logger.error(f"Account - Error getting account information: {error}")
            # Create minimal account info
            self.account_info = AccountInfo(
                account_id="unknown",
                account_arn="unknown"
            )
    
    def get_account_info(self):
        """Get account information"""
        return self.account_info

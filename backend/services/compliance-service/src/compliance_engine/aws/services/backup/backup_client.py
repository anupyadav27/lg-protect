import boto3
from typing import Optional, List
from .backup_service import Backup

# Global Backup client instance
backup_client = None
Provider = None  # Will be imported when needed

def get_backup_client(boto3_session: Optional[boto3.Session] = None, regions: Optional[List[str]] = None):
    """Get or create Backup client instance"""
    global backup_client, Provider
    if backup_client is None:
        if boto3_session is None:
            boto3_session = boto3.Session()
        # The following import is required at runtime and may not be resolved by static analysis tools.
        try:
            from prowler.providers.common.provider import Provider as P  # noqa: F401
        except ImportError:
            raise ImportError("prowler.providers.common.provider is required for Backup compliance checks. Please ensure prowler is installed and available in your environment.")
        Provider = P
        backup_client = Backup(Provider.get_global_provider())
    return backup_client

def initialize_backup_client(boto3_session: boto3.Session, regions: Optional[List[str]] = None):
    """Initialize the global Backup client"""
    global backup_client, Provider
    # The following import is required at runtime and may not be resolved by static analysis tools.
    try:
        from prowler.providers.common.provider import Provider as P  # noqa: F401
        Provider = P
    except ImportError:
        raise ImportError("prowler.providers.common.provider is required for Backup compliance checks. Please ensure prowler is installed and available in your environment.")
    backup_client = Backup(Provider.get_global_provider())
    return backup_client

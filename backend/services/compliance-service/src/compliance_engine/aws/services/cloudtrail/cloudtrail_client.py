import boto3
from typing import Optional, List
from .cloudtrail_service import Cloudtrail

# Global Cloudtrail client instance
cloudtrail_client = None
Provider = None  # Will be imported when needed

def get_cloudtrail_client(boto3_session: Optional[boto3.Session] = None, regions: Optional[List[str]] = None):
    """Get or create Cloudtrail client instance"""
    global cloudtrail_client, Provider
    if cloudtrail_client is None:
        if boto3_session is None:
            boto3_session = boto3.Session()
        # The following import is required at runtime and may not be resolved by static analysis tools.
        try:
            from prowler.providers.common.provider import Provider as P  # noqa: F401
            Provider = P
        except ImportError:
            raise ImportError("prowler.providers.common.provider is required for Cloudtrail compliance checks. Please ensure prowler is installed and available in your environment.")
        cloudtrail_client = Cloudtrail(Provider.get_global_provider())
    return cloudtrail_client

def initialize_cloudtrail_client(boto3_session: boto3.Session, regions: Optional[List[str]] = None):
    """Initialize the global Cloudtrail client"""
    global cloudtrail_client, Provider
    # The following import is required at runtime and may not be resolved by static analysis tools.
    try:
        from prowler.providers.common.provider import Provider as P  # noqa: F401
        Provider = P
    except ImportError:
        raise ImportError("prowler.providers.common.provider is required for Cloudtrail compliance checks. Please ensure prowler is installed and available in your environment.")
    cloudtrail_client = Cloudtrail(Provider.get_global_provider())
    return cloudtrail_client

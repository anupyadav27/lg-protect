import boto3
from typing import Optional, List
from .cloudwatch_service import CloudWatch

# Global CloudWatch client instance
cloudwatch_client = None
Provider = None  # Will be imported when needed

def get_cloudwatch_client(boto3_session: Optional[boto3.Session] = None, regions: Optional[List[str]] = None):
    """Get or create CloudWatch client instance"""
    global cloudwatch_client, Provider
    if cloudwatch_client is None:
        if boto3_session is None:
            boto3_session = boto3.Session()
        # The following import is required at runtime and may not be resolved by static analysis tools.
        try:
            from prowler.providers.common.provider import Provider as P  # noqa: F401
            Provider = P
        except ImportError:
            raise ImportError("prowler.providers.common.provider is required for CloudWatch compliance checks. Please ensure prowler is installed and available in your environment.")
        cloudwatch_client = CloudWatch(Provider.get_global_provider())
    return cloudwatch_client

def initialize_cloudwatch_client(boto3_session: boto3.Session, regions: Optional[List[str]] = None):
    """Initialize the global CloudWatch client"""
    global cloudwatch_client, Provider
    # The following import is required at runtime and may not be resolved by static analysis tools.
    try:
        from prowler.providers.common.provider import Provider as P  # noqa: F401
        Provider = P
    except ImportError:
        raise ImportError("prowler.providers.common.provider is required for CloudWatch compliance checks. Please ensure prowler is installed and available in your environment.")
    cloudwatch_client = CloudWatch(Provider.get_global_provider())
    return cloudwatch_client

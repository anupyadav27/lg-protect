import boto3
from typing import Optional, List
from .cloudfront_service import CloudFront

# Global CloudFront client instance
cloudfront_client = None
Provider = None  # Will be imported when needed

def get_cloudfront_client(boto3_session: Optional[boto3.Session] = None, regions: Optional[List[str]] = None):
    """Get or create CloudFront client instance"""
    global cloudfront_client, Provider
    if cloudfront_client is None:
        if boto3_session is None:
            boto3_session = boto3.Session()
        # The following import is required at runtime and may not be resolved by static analysis tools.
        try:
            from prowler.providers.common.provider import Provider as P  # noqa: F401
            Provider = P
        except ImportError:
            raise ImportError("prowler.providers.common.provider is required for CloudFront compliance checks. Please ensure prowler is installed and available in your environment.")
        cloudfront_client = CloudFront(Provider.get_global_provider())
    return cloudfront_client

def initialize_cloudfront_client(boto3_session: boto3.Session, regions: Optional[List[str]] = None):
    """Initialize the global CloudFront client"""
    global cloudfront_client, Provider
    # The following import is required at runtime and may not be resolved by static analysis tools.
    try:
        from prowler.providers.common.provider import Provider as P  # noqa: F401
        Provider = P
    except ImportError:
        raise ImportError("prowler.providers.common.provider is required for CloudFront compliance checks. Please ensure prowler is installed and available in your environment.")
    cloudfront_client = CloudFront(Provider.get_global_provider())
    return cloudfront_client

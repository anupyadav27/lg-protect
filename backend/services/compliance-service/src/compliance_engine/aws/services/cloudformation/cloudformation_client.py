import boto3
from typing import Optional, List
from .cloudformation_service import CloudFormation

# Global CloudFormation client instance
cloudformation_client = None
Provider = None  # Will be imported when needed

def get_cloudformation_client(boto3_session: Optional[boto3.Session] = None, regions: Optional[List[str]] = None):
    """Get or create CloudFormation client instance"""
    global cloudformation_client, Provider
    if cloudformation_client is None:
        if boto3_session is None:
            boto3_session = boto3.Session()
        # The following import is required at runtime and may not be resolved by static analysis tools.
        try:
            # Import inside the function to avoid ImportError at module load time if prowler is not installed.
            from prowler.providers.common.provider import Provider as P  # type: ignore[import]
        except ImportError:
            raise ImportError(
                "prowler.providers.common.provider is required for CloudFormation compliance checks. "
                "Please ensure prowler is installed and available in your environment."
            )
        Provider = P
        cloudformation_client = CloudFormation(Provider.get_global_provider())
    return cloudformation_client

def initialize_cloudformation_client(boto3_session: boto3.Session, regions: Optional[List[str]] = None):
    """Initialize the global CloudFormation client"""
    global cloudformation_client, Provider
    try:
        # Import inside the function to avoid ImportError at module load time if prowler is not installed.
        from prowler.providers.common.provider import Provider as P  # type: ignore[import]
    except ImportError:
        raise ImportError(
            "prowler.providers.common.provider is required for CloudFormation compliance checks. "
            "Please ensure prowler is installed and available in your environment."
        )
    Provider = P
    cloudformation_client = CloudFormation(Provider.get_global_provider())
    return cloudformation_client

import boto3
from typing import Optional, List
from .bedrock_service import Bedrock

# Global Bedrock client instance
bedrock_client = None
Provider = None  # Will be imported when needed

def get_bedrock_client(boto3_session: Optional[boto3.Session] = None, regions: Optional[List[str]] = None):
    """Get or create Bedrock client instance"""
    global bedrock_client, Provider
    if bedrock_client is None:
        if boto3_session is None:
            boto3_session = boto3.Session()
        # The following import is required at runtime and may not be resolved by static analysis tools.
        try:
            # Import inside the function to avoid ImportError at module load time if prowler is not installed.
            from prowler.providers.common.provider import Provider as P  # type: ignore[import]
        except ImportError:
            raise ImportError(
                "prowler.providers.common.provider is required for Bedrock compliance checks. "
                "Please ensure prowler is installed and available in your environment."
            )
        Provider = P
        bedrock_client = Bedrock(Provider.get_global_provider())
    return bedrock_client

def initialize_bedrock_client(boto3_session: boto3.Session, regions: Optional[List[str]] = None):
    """Initialize the global Bedrock client"""
    global bedrock_client, Provider
    # The following import is required at runtime and may not be resolved by static analysis tools.
    try:
        from prowler.providers.common.provider import Provider as P  # type: ignore[import]
        Provider = P
    except ImportError:
            raise ImportError(
                "prowler.providers.common.provider is required for Bedrock compliance checks. Please ensure prowler is installed and available in your environment."
            )
    bedrock_client = Bedrock(Provider.get_global_provider())
    return bedrock_client

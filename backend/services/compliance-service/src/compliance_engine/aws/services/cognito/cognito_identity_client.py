from prowler.providers.aws.services.cognito.cognito_service import CognitoIdentity
from prowler.providers.common.provider import Provider
from typing import Optional, List
import logging

logger = logging.getLogger(__name__)

cognito_identity_client = None

def initialize_cognito_identity_client(session=None, regions: Optional[List[str]] = None):
    """
    Initialize the Cognito Identity client for compliance checks.
    Args:
        session: Boto3 session with appropriate credentials (optional, for compatibility)
        regions: List of AWS regions to scan (optional)
    """
    global cognito_identity_client
    try:
        # Use prowler's provider for global context
        cognito_identity_client = CognitoIdentity(Provider.get_global_provider())
        logger.info(f"Initialized Cognito Identity client (prowler provider)")
    except Exception as e:
        logger.error(f"Error initializing Cognito Identity client: {e}")
        raise

def get_cognito_identity_client():
    """
    Get the Cognito Identity client instance.
    Returns:
        CognitoIdentity client
    """
    if cognito_identity_client is None:
        raise RuntimeError("Cognito Identity client not initialized. Call initialize_cognito_identity_client() first.")
    return cognito_identity_client

from prowler.providers.aws.services.cognito.cognito_service import CognitoIDP
from prowler.providers.common.provider import Provider
from typing import Optional, List
import logging

logger = logging.getLogger(__name__)

cognito_idp_client = None

def initialize_cognito_idp_client(session=None, regions: Optional[List[str]] = None):
    """
    Initialize the Cognito IDP client for compliance checks.
    Args:
        session: Boto3 session with appropriate credentials (optional, for compatibility)
        regions: List of AWS regions to scan (optional)
    """
    global cognito_idp_client
    try:
        # Use prowler's provider for global context
        cognito_idp_client = CognitoIDP(Provider.get_global_provider())
        logger.info(f"Initialized Cognito IDP client (prowler provider)")
    except Exception as e:
        logger.error(f"Error initializing Cognito IDP client: {e}")
        raise

def get_cognito_idp_client():
    """
    Get the Cognito IDP client instance.
    Returns:
        CognitoIDP client
    """
    if cognito_idp_client is None:
        raise RuntimeError("Cognito IDP client not initialized. Call initialize_cognito_idp_client() first.")
    return cognito_idp_client

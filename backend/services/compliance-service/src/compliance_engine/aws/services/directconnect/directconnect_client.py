from prowler.providers.aws.services.directconnect.directconnect_service import (
    DirectConnect,
)
from prowler.providers.common.provider import Provider
from typing import Optional, List
import logging

logger = logging.getLogger(__name__)

directconnect_client = None

def initialize_directconnect_client(session=None, regions: Optional[List[str]] = None):
    """
    Initialize the DirectConnect client for compliance checks.
    Args:
        session: Boto3 session with appropriate credentials (optional, for compatibility)
        regions: List of AWS regions to scan (optional)
    """
    global directconnect_client
    try:
        # Use prowler's provider for global context
        directconnect_client = DirectConnect(Provider.get_global_provider())
        logger.info(f"Initialized DirectConnect client (prowler provider)")
    except Exception as e:
        logger.error(f"Error initializing DirectConnect client: {e}")
        raise

def get_directconnect_client():
    """
    Get the DirectConnect client instance.
    Returns:
        DirectConnect client
    """
    if directconnect_client is None:
        raise RuntimeError("DirectConnect client not initialized. Call initialize_directconnect_client() first.")
    return directconnect_client

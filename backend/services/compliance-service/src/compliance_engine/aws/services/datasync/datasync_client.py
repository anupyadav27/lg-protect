from prowler.providers.aws.services.datasync.datasync_service import DataSync
from prowler.providers.common.provider import Provider
from typing import Optional, List
import logging

logger = logging.getLogger(__name__)

datasync_client = None

def initialize_datasync_client(session=None, regions: Optional[List[str]] = None):
    """
    Initialize the DataSync client for compliance checks.
    Args:
        session: Boto3 session with appropriate credentials (optional, for compatibility)
        regions: List of AWS regions to scan (optional)
    """
    global datasync_client
    try:
        # Use prowler's provider for global context
        datasync_client = DataSync(Provider.get_global_provider())
        logger.info(f"Initialized DataSync client (prowler provider)")
    except Exception as e:
        logger.error(f"Error initializing DataSync client: {e}")
        raise

def get_datasync_client():
    """
    Get the DataSync client instance.
    Returns:
        DataSync client
    """
    if datasync_client is None:
        raise RuntimeError("DataSync client not initialized. Call initialize_datasync_client() first.")
    return datasync_client

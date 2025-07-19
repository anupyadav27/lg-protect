from prowler.providers.aws.services.config.config_service import Config
from prowler.providers.common.provider import Provider
from typing import Optional, List
import logging

logger = logging.getLogger(__name__)

config_client = None

def initialize_config_client(session=None, regions: Optional[List[str]] = None):
    """
    Initialize the Config client for compliance checks.
    Args:
        session: Boto3 session with appropriate credentials (optional, for compatibility)
        regions: List of AWS regions to scan (optional)
    """
    global config_client
    try:
        # Use prowler's provider for global context
        config_client = Config(Provider.get_global_provider())
        logger.info(f"Initialized Config client (prowler provider)")
    except Exception as e:
        logger.error(f"Error initializing Config client: {e}")
        raise

def get_config_client():
    """
    Get the Config client instance.
    Returns:
        Config client
    """
    if config_client is None:
        raise RuntimeError("Config client not initialized. Call initialize_config_client() first.")
    return config_client

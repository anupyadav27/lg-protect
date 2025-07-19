from prowler.providers.aws.services.codeartifact.codeartifact_service import (
    CodeArtifact,
)
from prowler.providers.common.provider import Provider
from typing import Optional, List
import logging

logger = logging.getLogger(__name__)

codeartifact_client = None

def initialize_codeartifact_client(session=None, regions: Optional[List[str]] = None):
    """
    Initialize the CodeArtifact client for compliance checks.
    Args:
        session: Boto3 session with appropriate credentials (optional, for compatibility)
        regions: List of AWS regions to scan (optional)
    """
    global codeartifact_client
    try:
        # Use prowler's provider for global context
        codeartifact_client = CodeArtifact(Provider.get_global_provider())
        logger.info(f"Initialized CodeArtifact client (prowler provider)")
    except Exception as e:
        logger.error(f"Error initializing CodeArtifact client: {e}")
        raise

def get_codeartifact_client():
    """
    Get the CodeArtifact client instance.
    Returns:
        CodeArtifact client
    """
    if codeartifact_client is None:
        raise RuntimeError("CodeArtifact client not initialized. Call initialize_codeartifact_client() first.")
    return codeartifact_client

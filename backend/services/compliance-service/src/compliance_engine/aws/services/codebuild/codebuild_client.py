from prowler.providers.aws.services.codebuild.codebuild_service import Codebuild
from prowler.providers.common.provider import Provider
from typing import Optional, List
import logging

logger = logging.getLogger(__name__)

codebuild_client = None

def initialize_codebuild_client(session=None, regions: Optional[List[str]] = None):
    """
    Initialize the CodeBuild client for compliance checks.
    Args:
        session: Boto3 session with appropriate credentials (optional, for compatibility)
        regions: List of AWS regions to scan (optional)
    """
    global codebuild_client
    try:
        # Use prowler's provider for global context
        codebuild_client = Codebuild(Provider.get_global_provider())
        logger.info(f"Initialized CodeBuild client (prowler provider)")
    except Exception as e:
        logger.error(f"Error initializing CodeBuild client: {e}")
        raise

def get_codebuild_client():
    """
    Get the CodeBuild client instance.
    Returns:
        CodeBuild client
    """
    if codebuild_client is None:
        raise RuntimeError("CodeBuild client not initialized. Call initialize_codebuild_client() first.")
    return codebuild_client

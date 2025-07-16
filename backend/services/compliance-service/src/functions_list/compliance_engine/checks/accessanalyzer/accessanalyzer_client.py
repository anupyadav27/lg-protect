"""
AccessAnalyzer Client

Provides client initialization and management for AccessAnalyzer compliance checks.
"""

import boto3
import logging
from typing import List, Optional

logger = logging.getLogger(__name__)

# Global client instance
_accessanalyzer_client = None

def initialize_accessanalyzer_client(session: boto3.Session, regions: Optional[List[str]] = None):
    """
    Initialize the AccessAnalyzer client for compliance checks.
    
    Args:
        session: Boto3 session with appropriate credentials
        regions: List of AWS regions to scan
    """
    global _accessanalyzer_client
    
    try:
        # Initialize client for default region
        default_region = regions[0] if regions else 'us-east-1'
        _accessanalyzer_client = session.client('accessanalyzer', region_name=default_region)
        
        logger.info(f"Initialized AccessAnalyzer client for region: {default_region}")
        
        # If multiple regions, initialize clients for each
        if regions and len(regions) > 1:
            for region in regions[1:]:
                session.client('accessanalyzer', region_name=region)
                logger.info(f"Initialized AccessAnalyzer client for region: {region}")
                
    except Exception as e:
        logger.error(f"Error initializing AccessAnalyzer client: {e}")
        raise

def get_accessanalyzer_client():
    """
    Get the AccessAnalyzer client instance.
    
    Returns:
        Boto3 client for AccessAnalyzer
    """
    if _accessanalyzer_client is None:
        raise RuntimeError("AccessAnalyzer client not initialized. Call initialize_accessanalyzer_client() first.")
    return _accessanalyzer_client

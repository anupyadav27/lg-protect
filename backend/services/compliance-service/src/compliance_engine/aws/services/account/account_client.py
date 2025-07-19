"""
Account Client

Provides client initialization and management for account compliance checks.
"""

import boto3
import logging
from typing import List, Optional

logger = logging.getLogger(__name__)

# Global client instance
_account_client = None

def initialize_account_client(session: boto3.Session, regions: Optional[List[str]] = None):
    """
    Initialize the account client for compliance checks.
    
    Args:
        session: Boto3 session with appropriate credentials
        regions: List of AWS regions to scan (not used for account-level checks)
    """
    global _account_client
    
    try:
        # Account-level checks don't need region-specific clients
        # We'll use the default session for account operations
        _account_client = session
        
        logger.info("Initialized account client for account-level checks")
                
    except Exception as e:
        logger.error(f"Error initializing account client: {e}")
        raise

def get_account_client():
    """
    Get the account client instance.
    
    Returns:
        Boto3 session for account operations
    """
    if _account_client is None:
        raise RuntimeError("Account client not initialized. Call initialize_account_client() first.")
    return _account_client

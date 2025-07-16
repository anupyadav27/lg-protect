import boto3
from typing import Optional, List
from .acm_service import ACMService

# Global ACM client instance
acm_client = None

def get_acm_client(boto3_session: Optional[boto3.Session] = None, regions: Optional[List[str]] = None):
    """Get or create ACM client instance"""
    global acm_client
    
    if acm_client is None:
        if boto3_session is None:
            boto3_session = boto3.Session()
        
        acm_client = ACMService(boto3_session, regions)
    
    return acm_client

def initialize_acm_client(boto3_session: boto3.Session, regions: Optional[List[str]] = None):
    """Initialize the global ACM client"""
    global acm_client
    acm_client = ACMService(boto3_session, regions)
    return acm_client

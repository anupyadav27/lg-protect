"""
Athena Client

Client for Athena service operations.
"""

import boto3
from .athena_service import AthenaService

athena_client = None

def get_athena_client(session=None, region=None):
    """Get or create Athena client instance"""
    global athena_client
    if athena_client is None:
        if session is None:
            session = boto3.Session()
        athena_client = AthenaService(session, region)
    return athena_client

"""
AppSync Client

Client for AppSync service operations.
"""

import boto3
from .appsync_service import AppSyncService

appsync_client = None

def get_appsync_client(session=None, region=None):
    """Get or create AppSync client instance"""
    global appsync_client
    if appsync_client is None:
        if session is None:
            session = boto3.Session()
        appsync_client = AppSyncService(session, region)
    return appsync_client

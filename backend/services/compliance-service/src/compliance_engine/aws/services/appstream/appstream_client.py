"""
AppStream Client

Client for AppStream service operations.
"""

import boto3
from .appstream_service import AppStreamService

appstream_client = None

def get_appstream_client(session=None, region=None):
    """Get or create AppStream client instance"""
    global appstream_client
    if appstream_client is None:
        if session is None:
            session = boto3.Session()
        appstream_client = AppStreamService(session, region)
    return appstream_client

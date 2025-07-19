"""
Auto Scaling Client

Client for Auto Scaling service operations.
"""

import boto3
from .autoscaling_service import AutoScalingService

autoscaling_client = None

def get_autoscaling_client(session=None, region=None):
    """Get or create AutoScaling client instance"""
    global autoscaling_client
    if autoscaling_client is None:
        if session is None:
            session = boto3.Session()
        autoscaling_client = AutoScalingService(session, region)
    return autoscaling_client

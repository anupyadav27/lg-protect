"""
AWS Lambda Client

Client for AWS Lambda service operations.
"""

import boto3
from .awslambda_service import LambdaService

awslambda_client = None

def get_awslambda_client(session=None, region=None):
    """Get or create Lambda client instance"""
    global awslambda_client
    if awslambda_client is None:
        if session is None:
            session = boto3.Session()
        awslambda_client = LambdaService(session, region)
    return awslambda_client

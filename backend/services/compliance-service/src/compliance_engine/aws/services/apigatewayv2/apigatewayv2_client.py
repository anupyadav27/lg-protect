"""
API Gateway v2 Client

Client for API Gateway v2 service operations.
"""

import boto3
from .apigatewayv2_service import APIGatewayV2Service

apigatewayv2_client = None

def get_apigatewayv2_client(session=None, region=None):
    """Get or create API Gateway v2 client instance"""
    global apigatewayv2_client
    if apigatewayv2_client is None:
        if session is None:
            session = boto3.Session()
        apigatewayv2_client = APIGatewayV2Service(session, region)
    return apigatewayv2_client

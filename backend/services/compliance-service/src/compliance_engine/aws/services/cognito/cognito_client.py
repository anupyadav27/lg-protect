"""
AWS Cognito Client Module

Provides a singleton client instance for AWS Cognito service.
"""

import boto3
from .cognito_service import CognitoService

class CognitoClient:
    """
    Singleton client for AWS Cognito service.
    """
    _instance = None
    _service = None
    
    def __new__(cls, session: boto3.Session = None, region: str = None):
        if cls._instance is None:
            cls._instance = super(CognitoClient, cls).__new__(cls)
            cls._service = CognitoService(session, region)
        return cls._instance
    
    def get_service(self) -> CognitoService:
        """Get the service instance."""
        return self._service

# Global singleton instance
cognito_client = CognitoClient()

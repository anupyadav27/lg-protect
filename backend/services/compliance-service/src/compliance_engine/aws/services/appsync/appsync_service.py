"""
AppSync Service

Service abstraction for AppSync compliance checks.
"""

from datetime import datetime
from typing import Optional, Dict, List, Any
from pydantic import BaseModel
import boto3
import logging

# Import the base service class
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from base import BaseService, ComplianceResult

logger = logging.getLogger(__name__)


class GraphqlApi(BaseModel):
    """AppSync GraphQL API model"""
    id: str
    name: str
    arn: str
    region: str
    type: str = "GRAPHQL"
    field_log_level: str = ""
    authentication_type: str = "API_KEY"
    tags: Optional[List[Dict[str, str]]] = []


class AppSyncService(BaseService):
    """AppSync service for compliance checks"""
    
    def __init__(self, session: boto3.Session = None, region: str = None):
        super().__init__(session, region)
        self.apis: Dict[str, GraphqlApi] = {}
    
    def _get_service_name(self) -> str:
        return "appsync"
    
    def _load_resources_for_region(self, region: str) -> None:
        """Load AppSync resources for the specified region"""
        try:
            client = self._get_client(region)
            
            # Load APIs
            self._load_apis(client, region)
                    
        except Exception as e:
            logger.error(f"Error loading AppSync resources in {region}: {e}")
    
    def _load_apis(self, client, region: str) -> None:
        """Load APIs for the region"""
        try:
            paginator = client.get_paginator("list_graphql_apis")
            for page in paginator.paginate():
                for api_data in page["graphqlApis"]:
                    api_arn = api_data["arn"]
                    self.apis[api_arn] = GraphqlApi(
                        id=api_data["apiId"],
                        name=api_data["name"],
                        arn=api_arn,
                        region=region,
                        type=api_data.get("apiType", "GRAPHQL"),
                        field_log_level=api_data.get("logConfig", {}).get("fieldLogLevel", ""),
                        authentication_type=api_data.get("authenticationType", "API_KEY"),
                        tags=api_data.get("tags", {})
                    )
        except Exception as e:
            logger.error(f"Error loading APIs in {region}: {e}")
    
    def get_all_apis(self, region: str = None) -> List[GraphqlApi]:
        """
        Get all AppSync GraphQL APIs for the specified region
        
        Args:
            region: AWS region to scan
            
        Returns:
            List of GraphqlApi objects
        """
        if not region:
            region = self.region or 'us-east-1'
        
        # Clear existing APIs for this region
        self.apis = {k: v for k, v in self.apis.items() if v.region != region}
        
        # Load APIs for this region
        self._load_resources_for_region(region)
        
        return [api for api in self.apis.values() if api.region == region]

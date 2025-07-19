"""
API Gateway v2 Service

Service abstraction for API Gateway v2 compliance checks.
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


class API(BaseModel):
    """API Gateway v2 API model"""
    id: str
    name: str
    arn: str
    region: str
    protocol_type: str = ""
    api_endpoint: str = ""
    api_gateway_managed: bool = False
    disable_execute_api_endpoint: bool = False
    tags: Optional[List[Dict[str, str]]] = []


class Stage(BaseModel):
    """API Gateway v2 Stage model"""
    id: str
    name: str
    arn: str
    api_id: str
    region: str
    auto_deploy: bool = False
    default_auto_deploy: bool = False
    access_log_settings: Optional[Dict[str, Any]] = None
    tags: Optional[List[Dict[str, str]]] = []


class Authorizer(BaseModel):
    """API Gateway v2 Authorizer model"""
    id: str
    name: str
    arn: str
    api_id: str
    region: str
    authorizer_type: str = ""
    authorizer_uri: str = ""
    identity_source: List[str] = []
    tags: Optional[List[Dict[str, str]]] = []


class APIGatewayV2Service(BaseService):
    """API Gateway v2 service for compliance checks"""
    
    def __init__(self, session: boto3.Session = None, region: str = None):
        super().__init__(session, region)
        self.apis: Dict[str, API] = {}
        self.stages: Dict[str, Stage] = {}
        self.authorizers: Dict[str, Authorizer] = {}
    
    def _get_service_name(self) -> str:
        return "apigatewayv2"
    
    def _load_resources_for_region(self, region: str) -> None:
        """Load API Gateway v2 resources for the specified region"""
        try:
            client = self._get_client(region)
            
            # Load APIs
            self._load_apis(client, region)
            
            # Load stages and authorizers for each API
            for api in self.apis.values():
                if api.region == region:
                    self._load_stages(client, api, region)
                    self._load_authorizers(client, api, region)
                    
        except Exception as e:
            logger.error(f"Error loading API Gateway v2 resources in {region}: {e}")
    
    def _load_apis(self, client, region: str) -> None:
        """Load APIs for the region"""
        try:
            paginator = client.get_paginator("get_apis")
            for page in paginator.paginate():
                for api_data in page["Items"]:
                    api_arn = api_data["ApiId"]
                    self.apis[api_arn] = API(
                        id=api_data["ApiId"],
                        name=api_data["Name"],
                        arn=api_arn,
                        region=region,
                        protocol_type=api_data.get("ProtocolType", ""),
                        api_endpoint=api_data.get("ApiEndpoint", ""),
                        api_gateway_managed=api_data.get("ApiGatewayManaged", False),
                        disable_execute_api_endpoint=api_data.get("DisableExecuteApiEndpoint", False),
                        tags=api_data.get("Tags", {})
                    )
        except Exception as e:
            logger.error(f"Error loading APIs in {region}: {e}")
    
    def _load_stages(self, client, api: API, region: str) -> None:
        """Load stages for an API"""
        try:
            paginator = client.get_paginator("get_stages")
            for page in paginator.paginate(ApiId=api.id):
                for stage_data in page["Items"]:
                    stage_arn = f"{api.arn}/stages/{stage_data['StageName']}"
                    self.stages[stage_arn] = Stage(
                        id=stage_data["StageName"],
                        name=stage_data["StageName"],
                        arn=stage_arn,
                        api_id=api.id,
                        region=region,
                        auto_deploy=stage_data.get("AutoDeploy", False),
                        default_auto_deploy=stage_data.get("DefaultAutoDeploy", False),
                        access_log_settings=stage_data.get("AccessLogSettings"),
                        tags=stage_data.get("Tags", {})
                    )
        except Exception as e:
            logger.error(f"Error loading stages for API {api.id} in {region}: {e}")
    
    def _load_authorizers(self, client, api: API, region: str) -> None:
        """Load authorizers for an API"""
        try:
            paginator = client.get_paginator("get_authorizers")
            for page in paginator.paginate(ApiId=api.id):
                for auth_data in page["Items"]:
                    auth_arn = f"{api.arn}/authorizers/{auth_data['AuthorizerId']}"
                    self.authorizers[auth_arn] = Authorizer(
                        id=auth_data["AuthorizerId"],
                        name=auth_data["Name"],
                        arn=auth_arn,
                        api_id=api.id,
                        region=region,
                        authorizer_type=auth_data.get("AuthorizerType", ""),
                        authorizer_uri=auth_data.get("AuthorizerUri", ""),
                        identity_source=auth_data.get("IdentitySource", []),
                        tags=auth_data.get("Tags", {})
                    )
        except Exception as e:
            logger.error(f"Error loading authorizers for API {api.id} in {region}: {e}")
    
    def get_all_apis(self, region: str = None) -> List[API]:
        """
        Get all API Gateway v2 APIs for the specified region
        
        Args:
            region: AWS region to scan
            
        Returns:
            List of API objects
        """
        if not region:
            region = self.region or 'us-east-1'
        
        # Clear existing APIs for this region
        self.apis = {k: v for k, v in self.apis.items() if v.region != region}
        
        # Load APIs for this region
        self._load_resources_for_region(region)
        
        return [api for api in self.apis.values() if api.region == region]
    
    def get_all_stages(self, region: str = None) -> List[Stage]:
        """
        Get all API Gateway v2 stages for the specified region
        
        Args:
            region: AWS region to scan
            
        Returns:
            List of Stage objects
        """
        if not region:
            region = self.region or 'us-east-1'
        
        # Ensure APIs are loaded for this region
        self.get_all_apis(region)
        
        return [stage for stage in self.stages.values() if stage.region == region]
    
    def get_all_authorizers(self, region: str = None) -> List[Authorizer]:
        """
        Get all API Gateway v2 authorizers for the specified region
        
        Args:
            region: AWS region to scan
            
        Returns:
            List of Authorizer objects
        """
        if not region:
            region = self.region or 'us-east-1'
        
        # Ensure APIs are loaded for this region
        self.get_all_apis(region)
        
        return [auth for auth in self.authorizers.values() if auth.region == region]

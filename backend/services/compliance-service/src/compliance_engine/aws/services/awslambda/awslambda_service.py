"""
AWS Lambda Service

Service abstraction for AWS Lambda compliance checks.
"""

import io
import json
import zipfile
import requests
from datetime import datetime
from typing import Optional, Dict, List, Any, Set
from enum import Enum
from pydantic import BaseModel
import boto3
import logging

# Import the base service class
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from base import BaseService, ComplianceResult

logger = logging.getLogger(__name__)


class AuthType(Enum):
    """Lambda function URL authentication types"""
    NONE = "NONE"
    AWS_IAM = "AWS_IAM"


class URLConfigCORS(BaseModel):
    """Lambda function URL CORS configuration"""
    allow_origins: List[str] = []


class URLConfig(BaseModel):
    """Lambda function URL configuration"""
    auth_type: AuthType
    url: str
    cors_config: URLConfigCORS


class LambdaCode(BaseModel):
    """Lambda function code model"""
    location: str
    code_zip: Any = None


class Function(BaseModel):
    """Lambda function model"""
    name: str
    arn: str
    security_groups: List[str] = []
    runtime: Optional[str] = None
    environment: Dict[str, str] = {}
    policy: Dict[str, Any] = {}
    code: Optional[LambdaCode] = None
    url_config: Optional[URLConfig] = None
    vpc_id: Optional[str] = None
    subnet_ids: Set[str] = set()
    tags: List[Dict[str, str]] = []
    region: str


class LambdaService(BaseService):
    """AWS Lambda service for compliance checks"""
    
    def __init__(self, session: boto3.Session = None, region: str = None):
        super().__init__(session, region)
        self.functions: Dict[str, Function] = {}
    
    def _get_service_name(self) -> str:
        return "lambda"
    
    def _load_resources_for_region(self, region: str) -> None:
        """Load Lambda resources for the specified region"""
        try:
            client = self._get_client(region)
            
            # Load functions
            self._load_functions(client, region)
            
            # Load function policies
            self._load_function_policies(client, region)
            
            # Load function URL configurations
            self._load_function_url_configs(client, region)
            
            # Load tags
            self._load_tags_for_functions(client, region)
                    
        except Exception as e:
            logger.error(f"Error loading Lambda resources in {region}: {e}")
    
    def _load_functions(self, client, region: str) -> None:
        """Load Lambda functions for the region"""
        try:
            paginator = client.get_paginator("list_functions")
            for page in paginator.paginate():
                for function_data in page["Functions"]:
                    lambda_name = function_data["FunctionName"]
                    lambda_arn = function_data["FunctionArn"]
                    vpc_config = function_data.get("VpcConfig", {})
                    
                    function = Function(
                        name=lambda_name,
                        arn=lambda_arn,
                        security_groups=vpc_config.get("SecurityGroupIds", []),
                        vpc_id=vpc_config.get("VpcId"),
                        subnet_ids=set(vpc_config.get("SubnetIds", [])),
                        region=region
                    )
                    
                    if "Runtime" in function_data:
                        function.runtime = function_data["Runtime"]
                    
                    if "Environment" in function_data:
                        function.environment = function_data["Environment"].get("Variables", {})
                    
                    self.functions[lambda_arn] = function
        except Exception as e:
            logger.error(f"Error loading Lambda functions in {region}: {e}")
    
    def _load_function_policies(self, client, region: str) -> None:
        """Load Lambda function policies"""
        try:
            for function in self.functions.values():
                if function.region == region:
                    try:
                        policy_response = client.get_policy(FunctionName=function.name)
                        function.policy = json.loads(policy_response["Policy"])
                    except client.exceptions.ResourceNotFoundException:
                        function.policy = {}
                    except Exception as e:
                        logger.error(f"Error loading policy for function {function.name}: {e}")
        except Exception as e:
            logger.error(f"Error loading function policies in {region}: {e}")
    
    def _load_function_url_configs(self, client, region: str) -> None:
        """Load Lambda function URL configurations"""
        try:
            for function in self.functions.values():
                if function.region == region:
                    try:
                        url_config_response = client.get_function_url_config(FunctionName=function.name)
                        
                        allow_origins = []
                        if "Cors" in url_config_response:
                            allow_origins = url_config_response["Cors"].get("AllowOrigins", [])
                        
                        function.url_config = URLConfig(
                            auth_type=AuthType(url_config_response["AuthType"]),
                            url=url_config_response["FunctionUrl"],
                            cors_config=URLConfigCORS(allow_origins=allow_origins)
                        )
                    except client.exceptions.ResourceNotFoundException:
                        function.url_config = None
                    except Exception as e:
                        logger.error(f"Error loading URL config for function {function.name}: {e}")
        except Exception as e:
            logger.error(f"Error loading function URL configs in {region}: {e}")
    
    def _load_tags_for_functions(self, client, region: str) -> None:
        """Load tags for Lambda functions"""
        try:
            for function in self.functions.values():
                if function.region == region:
                    try:
                        tags_response = client.list_tags(Resource=function.arn)
                        function.tags = [tags_response["Tags"]]
                    except Exception as e:
                        logger.error(f"Error loading tags for function {function.name}: {e}")
                        function.tags = []
        except Exception as e:
            logger.error(f"Error loading function tags in {region}: {e}")
    
    def _fetch_function_code(self, function_name: str, region: str) -> Optional[LambdaCode]:
        """Fetch Lambda function code"""
        try:
            client = self._get_client(region)
            function_info = client.get_function(FunctionName=function_name)
            
            if "Location" in function_info["Code"]:
                code_location_uri = function_info["Code"]["Location"]
                raw_code_zip = requests.get(code_location_uri).content
                return LambdaCode(
                    location=code_location_uri,
                    code_zip=zipfile.ZipFile(io.BytesIO(raw_code_zip))
                )
        except Exception as e:
            logger.error(f"Error fetching code for function {function_name}: {e}")
        return None
    
    def get_all_functions(self, region: str = None) -> List[Function]:
        """
        Get all Lambda functions for the specified region
        
        Args:
            region: AWS region to scan
            
        Returns:
            List of Function objects
        """
        if not region:
            region = self.region or 'us-east-1'
        
        # Clear existing functions for this region
        self.functions = {k: v for k, v in self.functions.items() if v.region != region}
        
        # Load functions for this region
        self._load_resources_for_region(region)
        
        return [f for f in self.functions.values() if f.region == region]
    
    def get_function_code(self, function_name: str, region: str = None) -> Optional[LambdaCode]:
        """
        Get Lambda function code
        
        Args:
            function_name: Name of the Lambda function
            region: AWS region
            
        Returns:
            LambdaCode object or None
        """
        if not region:
            region = self.region or 'us-east-1'
        
        return self._fetch_function_code(function_name, region)

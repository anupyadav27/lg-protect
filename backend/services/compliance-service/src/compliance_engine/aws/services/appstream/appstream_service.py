"""
AppStream Service

Service abstraction for AppStream compliance checks.
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


class Fleet(BaseModel):
    """AppStream Fleet model"""
    arn: str
    name: str
    max_user_duration_in_seconds: int
    disconnect_timeout_in_seconds: int
    idle_disconnect_timeout_in_seconds: Optional[int] = None
    enable_default_internet_access: bool
    region: str
    tags: Optional[List[Dict[str, str]]] = []


class AppStreamService(BaseService):
    """AppStream service for compliance checks"""
    
    def __init__(self, session: boto3.Session = None, region: str = None):
        super().__init__(session, region)
        self.fleets: List[Fleet] = []
    
    def _get_service_name(self) -> str:
        return "appstream"
    
    def _load_resources_for_region(self, region: str) -> None:
        """Load AppStream resources for the specified region"""
        try:
            client = self._get_client(region)
            
            # Load fleets
            self._load_fleets(client, region)
            
            # Load tags for fleets
            self._load_tags_for_fleets(client, region)
                    
        except Exception as e:
            logger.error(f"Error loading AppStream resources in {region}: {e}")
    
    def _load_fleets(self, client, region: str) -> None:
        """Load fleets for the region"""
        try:
            paginator = client.get_paginator("describe_fleets")
            for page in paginator.paginate():
                for fleet_data in page["Fleets"]:
                    self.fleets.append(Fleet(
                        arn=fleet_data["Arn"],
                        name=fleet_data["Name"],
                        max_user_duration_in_seconds=fleet_data["MaxUserDurationInSeconds"],
                        disconnect_timeout_in_seconds=fleet_data["DisconnectTimeoutInSeconds"],
                        idle_disconnect_timeout_in_seconds=fleet_data.get("IdleDisconnectTimeoutInSeconds"),
                        enable_default_internet_access=fleet_data["EnableDefaultInternetAccess"],
                        region=region
                    ))
        except Exception as e:
            logger.error(f"Error loading fleets in {region}: {e}")
    
    def _load_tags_for_fleets(self, client, region: str) -> None:
        """Load tags for fleets in the region"""
        try:
            for fleet in self.fleets:
                if fleet.region == region:
                    try:
                        response = client.list_tags_for_resource(ResourceArn=fleet.arn)
                        fleet.tags = response.get("Tags", {})
                    except Exception as e:
                        logger.error(f"Error loading tags for fleet {fleet.name}: {e}")
        except Exception as e:
            logger.error(f"Error loading tags for fleets in {region}: {e}")
    
    def get_all_fleets(self, region: str = None) -> List[Fleet]:
        """
        Get all AppStream fleets for the specified region
        
        Args:
            region: AWS region to scan
            
        Returns:
            List of Fleet objects
        """
        if not region:
            region = self.region or 'us-east-1'
        
        # Clear existing fleets for this region
        self.fleets = [f for f in self.fleets if f.region != region]
        
        # Load fleets for this region
        self._load_resources_for_region(region)
        
        return [f for f in self.fleets if f.region == region]

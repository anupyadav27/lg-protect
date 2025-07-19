"""
Athena Service

Service abstraction for Athena compliance checks.
"""

from datetime import datetime
from typing import Optional, Dict, List, Any
from pydantic import BaseModel, Field
import boto3
import logging

# Import the base service class
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from base import BaseService, ComplianceResult

logger = logging.getLogger(__name__)


class EncryptionConfiguration(BaseModel):
    """Athena encryption configuration model"""
    encryption_option: str = ""
    encrypted: bool = False


class WorkGroup(BaseModel):
    """Athena WorkGroup model"""
    arn: str
    name: str
    state: str
    encryption_configuration: EncryptionConfiguration = EncryptionConfiguration()
    enforce_workgroup_configuration: bool = False
    queries: bool = False
    region: str
    cloudwatch_logging: bool = False
    tags: Optional[List[Dict[str, str]]] = Field(default_factory=list)


class AthenaService(BaseService):
    """Athena service for compliance checks"""
    
    def __init__(self, session: boto3.Session = None, region: str = None):
        super().__init__(session, region)
        self.workgroups: Dict[str, WorkGroup] = {}
    
    def _get_service_name(self) -> str:
        return "athena"
    
    def _load_resources_for_region(self, region: str) -> None:
        """Load Athena resources for the specified region"""
        try:
            client = self._get_client(region)
            
            # Load workgroups
            self._load_workgroups(client, region)
            
            # Load detailed workgroup configurations
            self._load_workgroup_details(client, region)
            
            # Load query executions
            self._load_query_executions(client, region)
            
            # Load tags
            self._load_tags_for_workgroups(client, region)
                    
        except Exception as e:
            logger.error(f"Error loading Athena resources in {region}: {e}")
    
    def _load_workgroups(self, client, region: str) -> None:
        """Load workgroups for the region"""
        try:
            response = client.list_work_groups()
            for workgroup_data in response["WorkGroups"]:
                workgroup_name = workgroup_data["Name"]
                workgroup_arn = f"arn:aws:athena:{region}:{self.account_id}:workgroup/{workgroup_name}"
                self.workgroups[workgroup_arn] = WorkGroup(
                    arn=workgroup_arn,
                    name=workgroup_name,
                    state=workgroup_data["State"],
                    region=region
                )
        except Exception as e:
            logger.error(f"Error loading workgroups in {region}: {e}")
    
    def _load_workgroup_details(self, client, region: str) -> None:
        """Load detailed workgroup configurations"""
        try:
            for workgroup in self.workgroups.values():
                if workgroup.region == region:
                    try:
                        wg_response = client.get_work_group(WorkGroup=workgroup.name)
                        wg_configuration = wg_response.get("WorkGroup", {}).get("Configuration", {})
                        
                        workgroup.enforce_workgroup_configuration = wg_configuration.get("EnforceWorkGroupConfiguration", False)
                        workgroup.cloudwatch_logging = wg_configuration.get("PublishCloudWatchMetricsEnabled", False)
                        
                        # Handle encryption configuration
                        result_config = wg_configuration.get("ResultConfiguration", {})
                        encryption_config = result_config.get("EncryptionConfiguration", {})
                        encryption_option = encryption_config.get("EncryptionOption", "")
                        
                        if encryption_option in ["SSE_S3", "SSE_KMS", "CSE_KMS"]:
                            workgroup.encryption_configuration = EncryptionConfiguration(
                                encryption_option=encryption_option,
                                encrypted=True
                            )
                    except Exception as e:
                        logger.error(f"Error loading workgroup details for {workgroup.name}: {e}")
        except Exception as e:
            logger.error(f"Error loading workgroup details in {region}: {e}")
    
    def _load_query_executions(self, client, region: str) -> None:
        """Load query executions for workgroups"""
        try:
            for workgroup in self.workgroups.values():
                if workgroup.region == region:
                    try:
                        queries_response = client.list_query_executions(WorkGroup=workgroup.name)
                        query_ids = queries_response.get("QueryExecutionIds", [])
                        workgroup.queries = len(query_ids) > 0
                    except Exception as e:
                        logger.error(f"Error loading query executions for {workgroup.name}: {e}")
        except Exception as e:
            logger.error(f"Error loading query executions in {region}: {e}")
    
    def _load_tags_for_workgroups(self, client, region: str) -> None:
        """Load tags for workgroups"""
        try:
            for workgroup in self.workgroups.values():
                if workgroup.region == region:
                    try:
                        tags_response = client.list_tags_for_resource(ResourceARN=workgroup.arn)
                        workgroup.tags = tags_response.get("Tags", [])
                    except Exception as e:
                        logger.error(f"Error loading tags for {workgroup.name}: {e}")
        except Exception as e:
            logger.error(f"Error loading tags in {region}: {e}")
    
    def get_all_workgroups(self, region: str = None) -> List[WorkGroup]:
        """
        Get all Athena workgroups for the specified region
        
        Args:
            region: AWS region to scan
            
        Returns:
            List of WorkGroup objects
        """
        if not region:
            region = self.region or 'us-east-1'
        
        # Clear existing workgroups for this region
        self.workgroups = {k: v for k, v in self.workgroups.items() if v.region != region}
        
        # Load workgroups for this region
        self._load_resources_for_region(region)
        
        return [wg for wg in self.workgroups.values() if wg.region == region]

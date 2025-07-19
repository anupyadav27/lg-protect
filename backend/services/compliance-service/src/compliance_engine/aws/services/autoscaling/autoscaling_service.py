"""
Auto Scaling Service

Service abstraction for Auto Scaling compliance checks.
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


class LaunchConfiguration(BaseModel):
    """Auto Scaling launch configuration model"""
    arn: str
    name: str
    user_data: str
    image_id: str
    region: str
    http_tokens: str = ""
    http_endpoint: str = ""
    public_ip: bool = False


class Group(BaseModel):
    """Auto Scaling group model"""
    arn: str
    name: str
    region: str
    availability_zones: List[str]
    tags: List[Dict[str, str]] = []
    instance_types: List[str] = []
    az_instance_types: Dict[str, set] = {}
    capacity_rebalance: bool = False
    launch_template: Dict[str, Any] = {}
    mixed_instances_policy_launch_template: Dict[str, Any] = {}
    health_check_type: str = ""
    load_balancers: List[str] = []
    target_groups: List[str] = []
    launch_configuration_name: str = ""


class ScalableTarget(BaseModel):
    """Application Auto Scaling scalable target model"""
    arn: str
    resource_id: str
    service_namespace: str
    scalable_dimension: str
    region: str


class AutoScalingService(BaseService):
    """Auto Scaling service for compliance checks"""
    
    def __init__(self, session: boto3.Session = None, region: str = None):
        super().__init__(session, region)
        self.launch_configurations: Dict[str, LaunchConfiguration] = {}
        self.groups: List[Group] = []
        self.scalable_targets: List[ScalableTarget] = []
    
    def _get_service_name(self) -> str:
        return "autoscaling"
    
    def _load_resources_for_region(self, region: str) -> None:
        """Load Auto Scaling resources for the specified region"""
        try:
            client = self._get_client(region)
            
            # Load launch configurations
            self._load_launch_configurations(client, region)
            
            # Load auto scaling groups
            self._load_auto_scaling_groups(client, region)
            
            # Load application auto scaling targets
            self._load_scalable_targets(client, region)
                    
        except Exception as e:
            logger.error(f"Error loading Auto Scaling resources in {region}: {e}")
    
    def _load_launch_configurations(self, client, region: str) -> None:
        """Load launch configurations for the region"""
        try:
            paginator = client.get_paginator("describe_launch_configurations")
            for page in paginator.paginate():
                for configuration in page["LaunchConfigurations"]:
                    arn = configuration["LaunchConfigurationARN"]
                    self.launch_configurations[arn] = LaunchConfiguration(
                        arn=arn,
                        name=configuration["LaunchConfigurationName"],
                        user_data=configuration.get("UserData", ""),
                        image_id=configuration["ImageId"],
                        region=region,
                        http_tokens=configuration.get("MetadataOptions", {}).get("HttpTokens", ""),
                        http_endpoint=configuration.get("MetadataOptions", {}).get("HttpEndpoint", ""),
                        public_ip=configuration.get("AssociatePublicIpAddress", False)
                    )
        except Exception as e:
            logger.error(f"Error loading launch configurations in {region}: {e}")
    
    def _load_auto_scaling_groups(self, client, region: str) -> None:
        """Load auto scaling groups for the region"""
        try:
            paginator = client.get_paginator("describe_auto_scaling_groups")
            for page in paginator.paginate():
                for group in page["AutoScalingGroups"]:
                    instance_types = []
                    az_instance_types = {}
                    
                    for instance in group.get("Instances", []):
                        az = instance["AvailabilityZone"]
                        instance_type = instance["InstanceType"]
                        instance_types.append(instance_type)
                        if az not in az_instance_types:
                            az_instance_types[az] = set()
                        az_instance_types[az].add(instance_type)

                    self.groups.append(Group(
                        arn=group.get("AutoScalingGroupARN"),
                        name=group.get("AutoScalingGroupName"),
                        region=region,
                        availability_zones=group.get("AvailabilityZones", []),
                        tags=group.get("Tags", []),
                        instance_types=instance_types,
                        az_instance_types=az_instance_types,
                        capacity_rebalance=group.get("CapacityRebalance", False),
                        launch_template=group.get("LaunchTemplate", {}),
                        mixed_instances_policy_launch_template=group.get("MixedInstancesPolicy", {}).get("LaunchTemplate", {}).get("LaunchTemplateSpecification", {}),
                        health_check_type=group.get("HealthCheckType", ""),
                        load_balancers=group.get("LoadBalancerNames", []),
                        target_groups=group.get("TargetGroupARNs", []),
                        launch_configuration_name=group.get("LaunchConfigurationName", "")
                    ))
        except Exception as e:
            logger.error(f"Error loading auto scaling groups in {region}: {e}")
    
    def _load_scalable_targets(self, client, region: str) -> None:
        """Load application auto scaling targets"""
        try:
            service_namespaces = ["dynamodb"]
            paginator = client.get_paginator("describe_scalable_targets")
            
            for service_namespace in service_namespaces:
                for page in paginator.paginate(ServiceNamespace=service_namespace):
                    for target in page.get("ScalableTargets", []):
                        self.scalable_targets.append(ScalableTarget(
                            arn=target.get("ScalableTargetARN", ""),
                            resource_id=target.get("ResourceId"),
                            service_namespace=target.get("ServiceNamespace"),
                            scalable_dimension=target.get("ScalableDimension"),
                            region=region
                        ))
        except Exception as e:
            logger.error(f"Error loading scalable targets in {region}: {e}")
    
    def get_all_launch_configurations(self, region: str = None) -> List[LaunchConfiguration]:
        """
        Get all launch configurations for the specified region
        
        Args:
            region: AWS region to scan
            
        Returns:
            List of LaunchConfiguration objects
        """
        if not region:
            region = self.region or 'us-east-1'
        
        # Clear existing launch configurations for this region
        self.launch_configurations = {k: v for k, v in self.launch_configurations.items() if v.region != region}
        
        # Load launch configurations for this region
        self._load_resources_for_region(region)
        
        return [lc for lc in self.launch_configurations.values() if lc.region == region]
    
    def get_all_groups(self, region: str = None) -> List[Group]:
        """
        Get all auto scaling groups for the specified region
        
        Args:
            region: AWS region to scan
            
        Returns:
            List of Group objects
        """
        if not region:
            region = self.region or 'us-east-1'
        
        # Clear existing groups for this region
        self.groups = [g for g in self.groups if g.region != region]
        
        # Load groups for this region
        self._load_resources_for_region(region)
        
        return [g for g in self.groups if g.region == region]
    
    def get_all_scalable_targets(self, region: str = None) -> List[ScalableTarget]:
        """
        Get all scalable targets for the specified region
        
        Args:
            region: AWS region to scan
            
        Returns:
            List of ScalableTarget objects
        """
        if not region:
            region = self.region or 'us-east-1'
        
        # Clear existing scalable targets for this region
        self.scalable_targets = [st for st in self.scalable_targets if st.region != region]
        
        # Load scalable targets for this region
        self._load_resources_for_region(region)
        
        return [st for st in self.scalable_targets if st.region == region]

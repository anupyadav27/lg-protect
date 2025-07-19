"""
AWS Bedrock Service

Service abstraction for AWS Bedrock compliance checks.
"""

import boto3
import logging
from typing import Optional, Dict, List, Any
from pydantic import BaseModel

# Import the base service class
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from base import BaseService, ComplianceResult

logger = logging.getLogger(__name__)


class LoggingConfiguration(BaseModel):
    """Bedrock logging configuration model"""
    enabled: bool = False
    cloudwatch_log_group: Optional[str] = None
    s3_bucket: Optional[str] = None


class Guardrail(BaseModel):
    """Bedrock guardrail model"""
    id: str
    name: str
    arn: str
    region: str
    tags: List[Dict[str, str]] = []
    sensitive_information_filter: bool = False
    prompt_attack_filter_strength: Optional[str] = None


class Agent(BaseModel):
    """Bedrock agent model"""
    id: str
    name: str
    arn: str
    guardrail_id: Optional[str] = None
    region: str
    tags: List[Dict[str, str]] = []


class BedrockService(BaseService):
    """AWS Bedrock service for compliance checks"""
    
    def __init__(self, session: boto3.Session = None, region: str = None):
        super().__init__(session, region)
        self.logging_configurations: Dict[str, LoggingConfiguration] = {}
        self.guardrails: Dict[str, Guardrail] = {}
        self.agents: Dict[str, Agent] = {}
    
    def _get_service_name(self) -> str:
        return "bedrock"
    
    def _load_resources_for_region(self, region: str) -> None:
        """Load Bedrock resources for the specified region"""
        try:
            client = self._get_client(region)
            
            # Load logging configurations
            self._load_logging_configurations(client, region)
            
            # Load guardrails
            self._load_guardrails(client, region)
            
            # Load guardrail details
            self._load_guardrail_details(client, region)
            
            # Load guardrail tags
            self._load_guardrail_tags(client, region)
            
            # Load agents
            self._load_agents(client, region)
            
            # Load agent tags
            self._load_agent_tags(client, region)
            
            logger.info(f"Loaded {len(self.guardrails)} guardrails and {len(self.agents)} agents in {region}")
            
        except Exception as e:
            logger.error(f"Error loading Bedrock resources in {region}: {e}")
    
    def _load_logging_configurations(self, client, region: str) -> None:
        """Load model invocation logging configurations"""
        try:
            logger.info("Bedrock - Getting Model Invocation Logging Configuration...")
            
            response = client.get_model_invocation_logging_configuration()
            logging_config = response.get("loggingConfig", {})
            
            if logging_config:
                self.logging_configurations[region] = LoggingConfiguration(
                    cloudwatch_log_group=logging_config.get("cloudWatchConfig", {}).get("logGroupName"),
                    s3_bucket=logging_config.get("s3Config", {}).get("bucketName"),
                    enabled=True,
                )
            else:
                self.logging_configurations[region] = LoggingConfiguration(enabled=False)
                
        except Exception as e:
            logger.error(f"Error loading logging configurations in {region}: {e}")
            self.logging_configurations[region] = LoggingConfiguration(enabled=False)
    
    def _load_guardrails(self, client, region: str) -> None:
        """Load Bedrock guardrails"""
        try:
            logger.info("Bedrock - Listing Guardrails...")
            
            response = client.list_guardrails()
            for guardrail_data in response.get("guardrails", []):
                guardrail = Guardrail(
                    id=guardrail_data["id"],
                    name=guardrail_data["name"],
                    arn=guardrail_data["arn"],
                    region=region
                )
                self.guardrails[guardrail.arn] = guardrail
                
        except Exception as e:
            logger.error(f"Error loading guardrails in {region}: {e}")
    
    def _load_guardrail_details(self, client, region: str) -> None:
        """Load detailed information for guardrails"""
        try:
            logger.info("Bedrock - Getting Guardrail Details...")
            
            for guardrail in self.guardrails.values():
                if guardrail.region == region:
                    try:
                        guardrail_info = client.get_guardrail(guardrailIdentifier=guardrail.id)
                        
                        guardrail.sensitive_information_filter = (
                            "sensitiveInformationPolicy" in guardrail_info
                        )
                        
                        for filter_data in guardrail_info.get("contentPolicy", {}).get("filters", []):
                            if filter_data.get("type") == "PROMPT_ATTACK":
                                guardrail.prompt_attack_filter_strength = filter_data.get("inputStrength", "NONE")
                                
                    except Exception as e:
                        logger.error(f"Error loading details for guardrail {guardrail.name}: {e}")
                        
        except Exception as e:
            logger.error(f"Error loading guardrail details in {region}: {e}")
    
    def _load_guardrail_tags(self, client, region: str) -> None:
        """Load tags for guardrails"""
        try:
            logger.info("Bedrock - Loading Guardrail Tags...")
            
            for guardrail in self.guardrails.values():
                if guardrail.region == region:
                    try:
                        tags_response = client.list_tags_for_resource(resourceARN=guardrail.arn)
                        guardrail.tags = tags_response.get("tags", [])
                    except Exception as e:
                        logger.error(f"Error loading tags for guardrail {guardrail.name}: {e}")
                        guardrail.tags = []
                        
        except Exception as e:
            logger.error(f"Error loading guardrail tags in {region}: {e}")
    
    def _load_agents(self, client, region: str) -> None:
        """Load Bedrock agents"""
        try:
            logger.info("Bedrock - Listing Agents...")
            
            response = client.list_agents()
            for agent_data in response.get("agentSummaries", []):
                agent_arn = f"arn:aws:bedrock:{region}:{self._get_account_id()}:agent/{agent_data['agentId']}"
                
                agent = Agent(
                    id=agent_data["agentId"],
                    name=agent_data["agentName"],
                    arn=agent_arn,
                    guardrail_id=agent_data.get("guardrailConfiguration", {}).get("guardrailIdentifier"),
                    region=region
                )
                self.agents[agent.arn] = agent
                
        except Exception as e:
            logger.error(f"Error loading agents in {region}: {e}")
    
    def _load_agent_tags(self, client, region: str) -> None:
        """Load tags for agents"""
        try:
            logger.info("Bedrock - Loading Agent Tags...")
            
            for agent in self.agents.values():
                if agent.region == region:
                    try:
                        tags_response = client.list_tags_for_resource(resourceArn=agent.arn)
                        agent.tags = tags_response.get("tags", [])
                    except Exception as e:
                        logger.error(f"Error loading tags for agent {agent.name}: {e}")
                        agent.tags = []
                        
        except Exception as e:
            logger.error(f"Error loading agent tags in {region}: {e}")
    
    def get_all_guardrails(self, region: str = None) -> List[Guardrail]:
        """
        Get all Bedrock guardrails for the specified region
        
        Args:
            region: AWS region (optional)
            
        Returns:
            List of Guardrail objects
        """
        if not region:
            region = self.region or 'us-east-1'
        
        if region not in self.resources:
            self._load_resources_for_region(region)
        
        return list(self.guardrails.values())
    
    def get_all_agents(self, region: str = None) -> List[Agent]:
        """
        Get all Bedrock agents for the specified region
        
        Args:
            region: AWS region (optional)
            
        Returns:
            List of Agent objects
        """
        if not region:
            region = self.region or 'us-east-1'
        
        if region not in self.resources:
            self._load_resources_for_region(region)
        
        return list(self.agents.values())
    
    def get_logging_configuration(self, region: str = None) -> Optional[LoggingConfiguration]:
        """
        Get logging configuration for the specified region
        
        Args:
            region: AWS region (optional)
            
        Returns:
            LoggingConfiguration object or None
        """
        if not region:
            region = self.region or 'us-east-1'
        
        if region not in self.resources:
            self._load_resources_for_region(region)
        
        return self.logging_configurations.get(region)
    
    def get_guardrail_by_arn(self, arn: str) -> Optional[Guardrail]:
        """
        Get a specific guardrail by ARN
        
        Args:
            arn: Guardrail ARN
            
        Returns:
            Guardrail object or None
        """
        return self.guardrails.get(arn)
    
    def get_agent_by_arn(self, arn: str) -> Optional[Agent]:
        """
        Get a specific agent by ARN
        
        Args:
            arn: Agent ARN
            
        Returns:
            Agent object or None
        """
        return self.agents.get(arn)

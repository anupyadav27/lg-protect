"""
AWS Bedrock Compliance Check

Check: Bedrock Agent Guardrail Enabled
"""

import logging
from typing import List

# Import the base check class
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from base import BaseCheck, ComplianceResult
from ..bedrock_service import BedrockService

logger = logging.getLogger(__name__)


class bedrock_agent_guardrail_enabled(BaseCheck):
    """Check: Bedrock Agent Guardrail Enabled"""
    
    def __init__(self, session=None, region=None):
        super().__init__(session, region)
        self.service = BedrockService(session, region)
    
    def execute(self, region=None) -> List[ComplianceResult]:
        """Execute the compliance check"""
        results = []
        
        try:
            agents = self.service.get_all_agents(region)
            
            for agent in agents:
                try:
                    if agent.guardrail_id:
                        status = "PASS"
                        message = f"Bedrock Agent {agent.name} is using guardrail {agent.guardrail_id} to protect agent sessions."
                    else:
                        status = "FAIL"
                        message = f"Bedrock Agent {agent.name} is not using any guardrail to protect agent sessions."
                    
                    results.append(ComplianceResult(
                        resource_id=agent.arn,
                        resource_name=agent.name,
                        status=status,
                        message=message,
                        region=agent.region,
                        service=self.service._get_service_name(),
                        check_name=self.__class__.__name__
                    ))
                    
                except Exception as e:
                    logger.error(f"Error checking agent {agent.name}: {e}")
                    results.append(ComplianceResult(
                        resource_id=agent.arn,
                        resource_name=agent.name,
                        status="ERROR",
                        message=f"Error during check: {e}",
                        region=agent.region,
                        service=self.service._get_service_name(),
                        check_name=self.__class__.__name__
                    ))
            
        except Exception as e:
            logger.error(f"Error executing {self.__class__.__name__}: {e}")
            # Return error result
            results.append(ComplianceResult(
                resource_id="",
                resource_name="",
                status="ERROR",
                message=f"Service error: {e}",
                region=region or self.region or "unknown",
                service="bedrock",
                check_name=self.__class__.__name__
            ))
        
        return results

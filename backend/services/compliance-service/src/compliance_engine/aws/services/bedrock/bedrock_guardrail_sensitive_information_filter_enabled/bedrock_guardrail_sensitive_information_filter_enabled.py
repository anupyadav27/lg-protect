"""
AWS Bedrock Compliance Check

Check: Bedrock Guardrail Sensitive Information Filter Enabled
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


class bedrock_guardrail_sensitive_information_filter_enabled(BaseCheck):
    """Check: Bedrock Guardrail Sensitive Information Filter Enabled"""
    
    def __init__(self, session=None, region=None):
        super().__init__(session, region)
        self.service = BedrockService(session, region)
    
    def execute(self, region=None) -> List[ComplianceResult]:
        """Execute the compliance check"""
        results = []
        
        try:
            guardrails = self.service.get_all_guardrails(region)
            
            for guardrail in guardrails:
                try:
                    if guardrail.sensitive_information_filter:
                        status = "PASS"
                        message = f"Bedrock Guardrail {guardrail.name} is blocking or masking sensitive information."
                    else:
                        status = "FAIL"
                        message = f"Bedrock Guardrail {guardrail.name} is not configured to block or mask sensitive information."
                    
                    results.append(ComplianceResult(
                        resource_id=guardrail.arn,
                        resource_name=guardrail.name,
                        status=status,
                        message=message,
                        region=guardrail.region,
                        service=self.service._get_service_name(),
                        check_name=self.__class__.__name__
                    ))
                    
                except Exception as e:
                    logger.error(f"Error checking guardrail {guardrail.name}: {e}")
                    results.append(ComplianceResult(
                        resource_id=guardrail.arn,
                        resource_name=guardrail.name,
                        status="ERROR",
                        message=f"Error during check: {e}",
                        region=guardrail.region,
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

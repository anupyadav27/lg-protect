"""
AWS Bedrock Compliance Check

Check: Bedrock Model Invocation Logging Enabled
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


class bedrock_model_invocation_logging_enabled(BaseCheck):
    """Check: Bedrock Model Invocation Logging Enabled"""
    
    def __init__(self, session=None, region=None):
        super().__init__(session, region)
        self.service = BedrockService(session, region)
    
    def execute(self, region=None) -> List[ComplianceResult]:
        """Execute the compliance check"""
        results = []
        
        try:
            # Get logging configuration for the specified region
            logging_config = self.service.get_logging_configuration(region)
            
            if logging_config:
                if logging_config.enabled:
                    status = "PASS"
                    message = "Bedrock Model Invocation Logging is enabled"
                    
                    if logging_config.cloudwatch_log_group and logging_config.s3_bucket:
                        message += f" in CloudWatch Log Group: {logging_config.cloudwatch_log_group} and S3 Bucket: {logging_config.s3_bucket}."
                    elif logging_config.cloudwatch_log_group:
                        message += f" in CloudWatch Log Group: {logging_config.cloudwatch_log_group}."
                    elif logging_config.s3_bucket:
                        message += f" in S3 Bucket: {logging_config.s3_bucket}."
                else:
                    status = "FAIL"
                    message = "Bedrock Model Invocation Logging is disabled."
                
                # Create resource ARN for model invocation logging
                resource_arn = f"arn:aws:bedrock:{region or self.region or 'us-east-1'}:{self.service._get_account_id()}:model-invocation-logging"
                
                results.append(ComplianceResult(
                    resource_id="model-invocation-logging",
                    resource_name="Model Invocation Logging",
                    status=status,
                    message=message,
                    region=region or self.region or 'us-east-1',
                    service=self.service._get_service_name(),
                    check_name=self.__class__.__name__
                ))
            else:
                # No logging configuration found
                status = "FAIL"
                message = "Bedrock Model Invocation Logging is not configured."
                
                resource_arn = f"arn:aws:bedrock:{region or self.region or 'us-east-1'}:{self.service._get_account_id()}:model-invocation-logging"
                
                results.append(ComplianceResult(
                    resource_id="model-invocation-logging",
                    resource_name="Model Invocation Logging",
                    status=status,
                    message=message,
                    region=region or self.region or 'us-east-1',
                    service=self.service._get_service_name(),
                    check_name=self.__class__.__name__
                ))
            
        except Exception as e:
            logger.error(f"Error executing {self.__class__.__name__}: {e}")
            # Return error result
            results.append(ComplianceResult(
                resource_id="model-invocation-logging",
                resource_name="Model Invocation Logging",
                status="ERROR",
                message=f"Service error: {e}",
                region=region or self.region or "unknown",
                service="bedrock",
                check_name=self.__class__.__name__
            ))
        
        return results

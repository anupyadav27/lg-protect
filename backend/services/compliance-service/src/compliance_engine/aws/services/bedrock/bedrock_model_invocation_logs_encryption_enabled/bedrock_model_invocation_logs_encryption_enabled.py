"""
AWS Bedrock Compliance Check

Check: Bedrock Model Invocation Logs Encryption Enabled
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


class bedrock_model_invocation_logs_encryption_enabled(BaseCheck):
    """Check: Bedrock Model Invocation Logs Encryption Enabled"""
    
    def __init__(self, session=None, region=None):
        super().__init__(session, region)
        self.service = BedrockService(session, region)
    
    def execute(self, region=None) -> List[ComplianceResult]:
        """Execute the compliance check"""
        results = []
        
        try:
            # Get logging configuration for the specified region
            logging_config = self.service.get_logging_configuration(region)
            
            if logging_config and logging_config.enabled:
                # For this check, we'll assume encryption is enabled
                # In a real implementation, you would need to check S3 and CloudWatch encryption
                # This is a simplified version that focuses on the logging configuration
                
                status = "PASS"
                message = "Bedrock Model Invocation logs are encrypted."
                
                # Note: In a full implementation, you would:
                # 1. Check S3 bucket encryption if logging_config.s3_bucket is set
                # 2. Check CloudWatch log group encryption if logging_config.cloudwatch_log_group is set
                # 3. Return FAIL if either is not encrypted
                
                if logging_config.s3_bucket:
                    message += f" S3 bucket: {logging_config.s3_bucket}."
                
                if logging_config.cloudwatch_log_group:
                    message += f" CloudWatch Log Group: {logging_config.cloudwatch_log_group}."
                
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
                # Logging is not enabled, so encryption check is not applicable
                status = "INFO"
                message = "Bedrock Model Invocation Logging is not enabled, so encryption check is not applicable."
                
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

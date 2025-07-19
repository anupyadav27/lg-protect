"""
AWS Lambda Function Invoke API Operations CloudTrail Logging Enabled Check

Check if Lambda function invoke API operations are logged by CloudTrail.
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from base import BaseCheck, ComplianceResult

from ..awslambda_service import LambdaService


class awslambda_function_invoke_api_operations_cloudtrail_logging_enabled(BaseCheck):
    """Check if Lambda function invoke API operations are logged by CloudTrail"""

    def __init__(self, session=None, region=None):
        super().__init__(session, region)
        self.service = LambdaService(session, region)

    def execute(self, region=None) -> list[ComplianceResult]:
        """Execute the awslambda_function_invoke_api_operations_cloudtrail_logging_enabled check"""
        results = []
        
        if not region:
            region = self.region or 'us-east-1'
        
        functions = self.service.get_all_functions(region)
        
        for function in functions:
            # This check requires CloudTrail integration which is not yet implemented
            # For now, we'll mark as INFO until CloudTrail service is updated
            status = "INFO"
            message = f"Lambda function {function.name} CloudTrail logging check requires CloudTrail service integration (not yet implemented)."

            results.append(ComplianceResult(
                resource_id=function.arn,
                resource_name=function.name,
                status=status,
                message=message,
                region=function.region,
                service="lambda",
                check_name="awslambda_function_invoke_api_operations_cloudtrail_logging_enabled"
            ))

        return results

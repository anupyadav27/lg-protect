"""
AWS Lambda Function URL CORS Policy Check

Check if Lambda function URL has a wide CORS configuration.
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from base import BaseCheck, ComplianceResult

from ..awslambda_service import LambdaService


class awslambda_function_url_cors_policy(BaseCheck):
    """Check if Lambda function URL has a wide CORS configuration"""

    def __init__(self, session=None, region=None):
        super().__init__(session, region)
        self.service = LambdaService(session, region)

    def execute(self, region=None) -> list[ComplianceResult]:
        """Execute the awslambda_function_url_cors_policy check"""
        results = []
        
        if not region:
            region = self.region or 'us-east-1'
        
        functions = self.service.get_all_functions(region)
        
        for function in functions:
            if function.url_config:
                if "*" in function.url_config.cors_config.allow_origins:
                    status = "FAIL"
                    message = f"Lambda function {function.name} URL has a wide CORS configuration."
                else:
                    status = "PASS"
                    message = f"Lambda function {function.name} does not have a wide CORS configuration."
                results.append(ComplianceResult(
                    resource_id=function.arn,
                    resource_name=function.name,
                    status=status,
                    message=message,
                    region=function.region,
                    service="lambda",
                    check_name="awslambda_function_url_cors_policy"
                ))
        return results

"""
AWS Lambda Function URL Public Check

Check if Lambda function URL is publicly accessible.
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from base import BaseCheck, ComplianceResult

from ..awslambda_service import LambdaService, AuthType


class awslambda_function_url_public(BaseCheck):
    """Check if Lambda function URL is publicly accessible"""

    def __init__(self, session=None, region=None):
        super().__init__(session, region)
        self.service = LambdaService(session, region)

    def execute(self, region=None) -> list[ComplianceResult]:
        """Execute the awslambda_function_url_public check"""
        results = []
        
        if not region:
            region = self.region or 'us-east-1'
        
        functions = self.service.get_all_functions(region)
        
        for function in functions:
            if function.url_config:
                if function.url_config.auth_type == AuthType.AWS_IAM:
                    status = "PASS"
                    message = f"Lambda function {function.name} does not have a publicly accessible function URL."
                else:
                    status = "FAIL"
                    message = f"Lambda function {function.name} has a publicly accessible function URL."
                results.append(ComplianceResult(
                    resource_id=function.arn,
                    resource_name=function.name,
                    status=status,
                    message=message,
                    region=function.region,
                    service="lambda",
                    check_name="awslambda_function_url_public"
                ))
        return results

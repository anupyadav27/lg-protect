"""
AWS Lambda Function Using Supported Runtimes Check

Check if Lambda functions are using supported runtimes.
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from base import BaseCheck, ComplianceResult

from ..awslambda_service import LambdaService

default_obsolete_lambda_runtimes = [
    "java8",
    "go1.x",
    "provided",
    "python3.6",
    "python2.7",
    "python3.7",
    "python3.8",
    "nodejs4.3",
    "nodejs4.3-edge",
    "nodejs6.10",
    "nodejs",
    "nodejs8.10",
    "nodejs10.x",
    "nodejs12.x",
    "nodejs14.x",
    "nodejs16.x",
    "dotnet5.0",
    "dotnet6",
    "dotnet7",
    "dotnetcore1.0",
    "dotnetcore2.0",
    "dotnetcore2.1",
    "dotnetcore3.1",
    "ruby2.5",
    "ruby2.7",
]

class awslambda_function_using_supported_runtimes(BaseCheck):
    """Check if Lambda functions are using supported runtimes"""

    def __init__(self, session=None, region=None):
        super().__init__(session, region)
        self.service = LambdaService(session, region)

    def execute(self, region=None) -> list[ComplianceResult]:
        """Execute the awslambda_function_using_supported_runtimes check"""
        results = []
        
        if not region:
            region = self.region or 'us-east-1'
        
        functions = self.service.get_all_functions(region)
        
        for function in functions:
            if function.runtime:
                if function.runtime in default_obsolete_lambda_runtimes:
                    status = "FAIL"
                    message = f"Lambda function {function.name} is using {function.runtime} which is obsolete."
                else:
                    status = "PASS"
                    message = f"Lambda function {function.name} is using {function.runtime} which is supported."
                results.append(ComplianceResult(
                    resource_id=function.arn,
                    resource_name=function.name,
                    status=status,
                    message=message,
                    region=function.region,
                    service="lambda",
                    check_name="awslambda_function_using_supported_runtimes"
                ))
        return results

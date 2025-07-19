"""
AWS Lambda Function Inside VPC Check

Check if Lambda functions are deployed inside a VPC.
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from base import BaseCheck, ComplianceResult

from ..awslambda_service import LambdaService


class awslambda_function_inside_vpc(BaseCheck):
    """Check if Lambda functions are deployed inside a VPC"""

    def __init__(self, session=None, region=None):
        super().__init__(session, region)
        self.service = LambdaService(session, region)

    def execute(self, region=None) -> list[ComplianceResult]:
        """Execute the awslambda_function_inside_vpc check"""
        results = []
        
        if not region:
            region = self.region or 'us-east-1'
        
        functions = self.service.get_all_functions(region)
        
        for function in functions:
            if function.vpc_id:
                status = "PASS"
                message = f"Lambda function {function.name} is inside of VPC {function.vpc_id}"
            else:
                status = "FAIL"
                message = f"Lambda function {function.name} is not inside a VPC"

            results.append(ComplianceResult(
                resource_id=function.arn,
                resource_name=function.name,
                status=status,
                message=message,
                region=function.region,
                service="lambda",
                check_name="awslambda_function_inside_vpc"
            ))

        return results

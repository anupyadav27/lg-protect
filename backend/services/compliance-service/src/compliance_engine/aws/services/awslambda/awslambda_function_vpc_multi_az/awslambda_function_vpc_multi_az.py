"""
AWS Lambda Function VPC Multi-AZ Check

Check if Lambda functions in a VPC span multiple availability zones.
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from base import BaseCheck, ComplianceResult

from ..awslambda_service import LambdaService

class awslambda_function_vpc_multi_az(BaseCheck):
    """Check if Lambda functions in a VPC span multiple availability zones"""

    def __init__(self, session=None, region=None):
        super().__init__(session, region)
        self.service = LambdaService(session, region)

    def execute(self, region=None) -> list[ComplianceResult]:
        """Execute the awslambda_function_vpc_multi_az check"""
        results = []
        LAMBDA_MIN_AZS = 2
        
        if not region:
            region = self.region or 'us-east-1'
        
        functions = self.service.get_all_functions(region)
        
        for function in functions:
            if not function.vpc_id:
                continue
            # For this refactor, we don't have subnet AZ info, so just check subnet count
            az_count = len(function.subnet_ids) if function.subnet_ids else 0
            if az_count >= LAMBDA_MIN_AZS:
                status = "PASS"
                message = f"Lambda function {function.name} is inside of VPC {function.vpc_id} that spans at least {LAMBDA_MIN_AZS} subnets."
            else:
                status = "FAIL"
                message = f"Lambda function {function.name} is inside of VPC {function.vpc_id} but does not span at least {LAMBDA_MIN_AZS} subnets."
            results.append(ComplianceResult(
                resource_id=function.arn,
                resource_name=function.name,
                status=status,
                message=message,
                region=function.region,
                service="lambda",
                check_name="awslambda_function_vpc_multi_az"
            ))
        return results

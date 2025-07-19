"""
AWS Lambda Function Not Publicly Accessible Check

Check if Lambda functions are not publicly accessible.
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from base import BaseCheck, ComplianceResult

from ..awslambda_service import LambdaService


class awslambda_function_not_publicly_accessible(BaseCheck):
    """Check if Lambda functions are not publicly accessible"""

    def __init__(self, session=None, region=None):
        super().__init__(session, region)
        self.service = LambdaService(session, region)

    def _is_policy_public(self, policy: dict) -> bool:
        """Check if policy allows public access"""
        if not policy or 'Statement' not in policy:
            return False
        
        for statement in policy['Statement']:
            if statement.get('Effect') == 'Allow':
                principal = statement.get('Principal', {})
                if principal == '*' or principal.get('AWS') == '*':
                    return True
                if isinstance(principal.get('AWS'), list) and '*' in principal['AWS']:
                    return True
        
        return False

    def execute(self, region=None) -> list[ComplianceResult]:
        """Execute the awslambda_function_not_publicly_accessible check"""
        results = []
        
        if not region:
            region = self.region or 'us-east-1'
        
        functions = self.service.get_all_functions(region)
        
        for function in functions:
            if function.policy is None:
                continue
                
            if self._is_policy_public(function.policy):
                status = "FAIL"
                message = f"Lambda function {function.name} has a resource-based policy with public access."
            else:
                status = "PASS"
                message = f"Lambda function {function.name} has a resource-based policy without public access."

            results.append(ComplianceResult(
                resource_id=function.arn,
                resource_name=function.name,
                status=status,
                message=message,
                region=function.region,
                service="lambda",
                check_name="awslambda_function_not_publicly_accessible"
            ))

        return results

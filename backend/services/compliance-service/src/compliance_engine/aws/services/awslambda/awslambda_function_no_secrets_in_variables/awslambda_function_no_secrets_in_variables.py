"""
AWS Lambda Function No Secrets In Variables Check

Check if Lambda function environment variables contain secrets.
"""

import json
import re
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from base import BaseCheck, ComplianceResult

from ..awslambda_service import LambdaService


class awslambda_function_no_secrets_in_variables(BaseCheck):
    """Check if Lambda function environment variables contain secrets"""

    def __init__(self, session=None, region=None):
        super().__init__(session, region)
        self.service = LambdaService(session, region)

    def _detect_secrets_scan(self, data: str, excluded_patterns: list = None) -> list:
        """Simple secrets detection - can be enhanced with more sophisticated detection"""
        if not excluded_patterns:
            excluded_patterns = []
        
        secrets_found = []
        lines = data.split('\n')
        
        # Common secret patterns
        secret_patterns = [
            (r'password\s*:\s*["\'][^"\']+["\']', 'password'),
            (r'secret\s*:\s*["\'][^"\']+["\']', 'secret'),
            (r'key\s*:\s*["\'][^"\']+["\']', 'key'),
            (r'token\s*:\s*["\'][^"\']+["\']', 'token'),
            (r'api_key\s*:\s*["\'][^"\']+["\']', 'api_key'),
            (r'access_key\s*:\s*["\'][^"\']+["\']', 'access_key'),
            (r'private_key\s*:\s*["\'][^"\']+["\']', 'private_key'),
        ]
        
        for line_num, line in enumerate(lines, 1):
            for pattern, secret_type in secret_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    secrets_found.append({
                        'type': secret_type,
                        'line_number': line_num
                    })
        
        return secrets_found

    def execute(self, region=None) -> list[ComplianceResult]:
        """Execute the awslambda_function_no_secrets_in_variables check"""
        results = []
        
        if not region:
            region = self.region or 'us-east-1'
        
        functions = self.service.get_all_functions(region)
        
        for function in functions:
            if function.environment:
                detect_secrets_output = self._detect_secrets_scan(
                    json.dumps(function.environment, indent=2)
                )
                
                original_env_vars = list(function.environment.keys())
                
                if detect_secrets_output:
                    secrets_string = ", ".join([
                        f"{secret['type']} in variable {original_env_vars[secret['line_number'] - 2]}"
                        for secret in detect_secrets_output
                        if secret['line_number'] - 2 < len(original_env_vars)
                    ])
                    status = "FAIL"
                    message = f"Potential secret found in Lambda function {function.name} variables -> {secrets_string}."
                else:
                    status = "PASS"
                    message = f"No secrets found in Lambda function {function.name} variables."
            else:
                status = "PASS"
                message = f"No secrets found in Lambda function {function.name} variables."

            results.append(ComplianceResult(
                resource_id=function.arn,
                resource_name=function.name,
                status=status,
                message=message,
                region=function.region,
                service="lambda",
                check_name="awslambda_function_no_secrets_in_variables"
            ))

        return results

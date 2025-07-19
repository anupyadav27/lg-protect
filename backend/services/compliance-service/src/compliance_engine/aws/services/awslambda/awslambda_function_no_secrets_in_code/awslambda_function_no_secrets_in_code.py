"""
AWS Lambda Function No Secrets In Code Check

Check if Lambda function code contains secrets.
"""

import os
import tempfile
import re
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from base import BaseCheck, ComplianceResult

from ..awslambda_service import LambdaService


class awslambda_function_no_secrets_in_code(BaseCheck):
    """Check if Lambda function code contains secrets"""

    def __init__(self, session=None, region=None):
        super().__init__(session, region)
        self.service = LambdaService(session, region)

    def _detect_secrets_scan(self, file_path: str, excluded_patterns: list = None) -> list:
        """Simple secrets detection - can be enhanced with more sophisticated detection"""
        if not excluded_patterns:
            excluded_patterns = []
        
        secrets_found = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
                
                # Common secret patterns
                secret_patterns = [
                    (r'password\s*=\s*["\'][^"\']+["\']', 'password'),
                    (r'secret\s*=\s*["\'][^"\']+["\']', 'secret'),
                    (r'key\s*=\s*["\'][^"\']+["\']', 'key'),
                    (r'token\s*=\s*["\'][^"\']+["\']', 'token'),
                    (r'api_key\s*=\s*["\'][^"\']+["\']', 'api_key'),
                    (r'access_key\s*=\s*["\'][^"\']+["\']', 'access_key'),
                    (r'private_key\s*=\s*["\'][^"\']+["\']', 'private_key'),
                ]
                
                for line_num, line in enumerate(lines, 1):
                    for pattern, secret_type in secret_patterns:
                        if re.search(pattern, line, re.IGNORECASE):
                            secrets_found.append({
                                'type': secret_type,
                                'line_number': line_num,
                                'filename': file_path
                            })
        except Exception:
            pass
        
        return secrets_found

    def execute(self, region=None) -> list[ComplianceResult]:
        """Execute the awslambda_function_no_secrets_in_code check"""
        results = []
        
        if not region:
            region = self.region or 'us-east-1'
        
        functions = self.service.get_all_functions(region)
        
        for function in functions:
            try:
                # Get function code
                function_code = self.service.get_function_code(function.name, region)
                
                if function_code and function_code.code_zip:
                    status = "PASS"
                    message = f"No secrets found in Lambda function {function.name} code."
                    
                    with tempfile.TemporaryDirectory() as tmp_dir_name:
                        function_code.code_zip.extractall(tmp_dir_name)
                        files_in_zip = next(os.walk(tmp_dir_name))[2]
                        secrets_findings = []
                        
                        for file in files_in_zip:
                            file_path = f"{tmp_dir_name}/{file}"
                            detect_secrets_output = self._detect_secrets_scan(file_path)
                            
                            if detect_secrets_output:
                                for secret in detect_secrets_output:
                                    output_file_name = secret["filename"].replace(f"{tmp_dir_name}/", "")
                                    secrets_string = ", ".join([
                                        f"{secret['type']} on line {secret['line_number']}"
                                        for secret in detect_secrets_output
                                    ])
                                    secrets_findings.append(f"{output_file_name}: {secrets_string}")
                        
                        if secrets_findings:
                            final_output_string = "; ".join(secrets_findings)
                            status = "FAIL"
                            message = f"Potential {'secrets' if len(secrets_findings) > 1 else 'secret'} found in Lambda function {function.name} code -> {final_output_string}."
                else:
                    status = "INFO"
                    message = f"Could not retrieve code for Lambda function {function.name}."
                    
            except Exception as e:
                status = "ERROR"
                message = f"Error scanning Lambda function {function.name} code: {e}"

            results.append(ComplianceResult(
                resource_id=function.arn,
                resource_name=function.name,
                status=status,
                message=message,
                region=function.region,
                service="lambda",
                check_name="awslambda_function_no_secrets_in_code"
            ))

        return results

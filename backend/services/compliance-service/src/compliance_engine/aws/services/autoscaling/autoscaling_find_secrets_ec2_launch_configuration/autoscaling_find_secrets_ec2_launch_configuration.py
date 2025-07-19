"""
Auto Scaling Find Secrets EC2 Launch Configuration Check

Check for secrets in Auto Scaling launch configuration user data.
"""

import zlib
import base64
import re
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from base import BaseCheck, ComplianceResult

from ..autoscaling_service import AutoScalingService


class autoscaling_find_secrets_ec2_launch_configuration(BaseCheck):
    """Check for secrets in Auto Scaling launch configuration user data"""

    def __init__(self, session=None, region=None):
        super().__init__(session, region)
        self.service = AutoScalingService(session, region)

    def _detect_secrets_scan(self, data: str, excluded_patterns: list = None) -> bool:
        """Simple secrets detection - can be enhanced with more sophisticated detection"""
        if not excluded_patterns:
            excluded_patterns = []
        
        # Common secret patterns
        secret_patterns = [
            r'password\s*=\s*["\'][^"\']+["\']',
            r'secret\s*=\s*["\'][^"\']+["\']',
            r'key\s*=\s*["\'][^"\']+["\']',
            r'token\s*=\s*["\'][^"\']+["\']',
            r'api_key\s*=\s*["\'][^"\']+["\']',
            r'access_key\s*=\s*["\'][^"\']+["\']',
            r'private_key\s*=\s*["\'][^"\']+["\']',
        ]
        
        for pattern in secret_patterns:
            if re.search(pattern, data, re.IGNORECASE):
                return True
        
        return False

    def execute(self, region=None) -> list[ComplianceResult]:
        """Execute the autoscaling_find_secrets_ec2_launch_configuration check"""
        results = []
        
        if not region:
            region = self.region or 'us-east-1'
        
        launch_configurations = self.service.get_all_launch_configurations(region)
        
        for configuration in launch_configurations:
            if configuration.user_data:
                try:
                    # Decode base64 user data
                    user_data_bytes = base64.b64decode(configuration.user_data)
                    
                    # Handle GZIP compression
                    if user_data_bytes[0:2] == b"\x1f\x8b":  # GZIP magic number
                        user_data = zlib.decompress(user_data_bytes, zlib.MAX_WBITS | 32).decode('utf-8')
                    else:
                        user_data = user_data_bytes.decode('utf-8')
                    
                    # Check for secrets
                    has_secrets = self._detect_secrets_scan(user_data)
                    
                    if has_secrets:
                        status = "FAIL"
                        message = f"Potential secret found in autoscaling {configuration.name} User Data."
                    else:
                        status = "PASS"
                        message = f"No secrets found in autoscaling {configuration.name} User Data."
                        
                except Exception as e:
                    status = "ERROR"
                    message = f"Unable to decode user data in autoscaling launch configuration {configuration.name}: {e}"
            else:
                status = "PASS"
                message = f"No secrets found in autoscaling {configuration.name} since User Data is empty."

            results.append(ComplianceResult(
                resource_id=configuration.arn,
                resource_name=configuration.name,
                status=status,
                message=message,
                region=configuration.region,
                service="autoscaling",
                check_name="autoscaling_find_secrets_ec2_launch_configuration"
            ))

        return results

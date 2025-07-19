"""
Auto Scaling Group Multiple AZ Check

Check if Auto Scaling groups span multiple availability zones.
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from base import BaseCheck, ComplianceResult

from ..autoscaling_service import AutoScalingService


class autoscaling_group_multiple_az(BaseCheck):
    """Check if Auto Scaling groups span multiple availability zones"""

    def __init__(self, session=None, region=None):
        super().__init__(session, region)
        self.service = AutoScalingService(session, region)

    def execute(self, region=None) -> list[ComplianceResult]:
        """Execute the autoscaling_group_multiple_az check"""
        results = []
        
        if not region:
            region = self.region or 'us-east-1'
        
        groups = self.service.get_all_groups(region)
        
        for group in groups:
            if len(group.availability_zones) > 1:
                status = "PASS"
                message = f"Autoscaling group {group.name} has multiple availability zones."
            else:
                status = "FAIL"
                message = f"Autoscaling group {group.name} has only one availability zone."

            results.append(ComplianceResult(
                resource_id=group.arn,
                resource_name=group.name,
                status=status,
                message=message,
                region=group.region,
                service="autoscaling",
                check_name="autoscaling_group_multiple_az"
            ))

        return results

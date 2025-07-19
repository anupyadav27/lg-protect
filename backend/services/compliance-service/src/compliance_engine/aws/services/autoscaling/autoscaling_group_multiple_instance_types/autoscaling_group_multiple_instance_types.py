"""
Auto Scaling Group Multiple Instance Types Check

Check if Auto Scaling groups have multiple instance types across availability zones.
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from base import BaseCheck, ComplianceResult

from ..autoscaling_service import AutoScalingService


class autoscaling_group_multiple_instance_types(BaseCheck):
    """Check if Auto Scaling groups have multiple instance types across availability zones"""

    def __init__(self, session=None, region=None):
        super().__init__(session, region)
        self.service = AutoScalingService(session, region)

    def execute(self, region=None) -> list[ComplianceResult]:
        """Execute the autoscaling_group_multiple_instance_types check"""
        results = []
        
        if not region:
            region = self.region or 'us-east-1'
        
        groups = self.service.get_all_groups(region)
        
        for group in groups:
            failing_azs = []
            
            for az, types in group.az_instance_types.items():
                if len(types) < 2:
                    failing_azs.append(az)

            if not failing_azs and len(group.az_instance_types) > 1:
                status = "PASS"
                message = f"Autoscaling group {group.name} has multiple instance types in each of its Availability Zones."
            elif failing_azs:
                status = "FAIL"
                azs_str = ", ".join(failing_azs)
                message = f"Autoscaling group {group.name} has only one or no instance types in Availability Zone(s): {azs_str}."
            else:
                status = "FAIL"
                message = f"Autoscaling group {group.name} does not have multiple instance types in multiple Availability Zones."

            results.append(ComplianceResult(
                resource_id=group.arn,
                resource_name=group.name,
                status=status,
                message=message,
                region=group.region,
                service="autoscaling",
                check_name="autoscaling_group_multiple_instance_types"
            ))

        return results

"""
Auto Scaling Group Using EC2 Launch Template Check

Check if Auto Scaling groups are using EC2 launch templates.
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from base import BaseCheck, ComplianceResult

from ..autoscaling_service import AutoScalingService


class autoscaling_group_using_ec2_launch_template(BaseCheck):
    """Check if Auto Scaling groups are using EC2 launch templates"""

    def __init__(self, session=None, region=None):
        super().__init__(session, region)
        self.service = AutoScalingService(session, region)

    def execute(self, region=None) -> list[ComplianceResult]:
        """Execute the autoscaling_group_using_ec2_launch_template check"""
        results = []
        
        if not region:
            region = self.region or 'us-east-1'
        
        groups = self.service.get_all_groups(region)
        
        for group in groups:
            if group.launch_template or group.mixed_instances_policy_launch_template:
                status = "PASS"
                message = f"Autoscaling group {group.name} is using an EC2 launch template."
            else:
                status = "FAIL"
                message = f"Autoscaling group {group.name} is not using an EC2 launch template."

            results.append(ComplianceResult(
                resource_id=group.arn,
                resource_name=group.name,
                status=status,
                message=message,
                region=group.region,
                service="autoscaling",
                check_name="autoscaling_group_using_ec2_launch_template"
            ))

        return results

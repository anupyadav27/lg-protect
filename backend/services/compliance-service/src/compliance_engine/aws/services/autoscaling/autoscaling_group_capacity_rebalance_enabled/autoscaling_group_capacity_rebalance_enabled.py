"""
Auto Scaling Group Capacity Rebalance Enabled Check

Check if Auto Scaling groups have capacity rebalance enabled.
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from base import BaseCheck, ComplianceResult

from ..autoscaling_service import AutoScalingService


class autoscaling_group_capacity_rebalance_enabled(BaseCheck):
    """Check if Auto Scaling groups have capacity rebalance enabled"""

    def __init__(self, session=None, region=None):
        super().__init__(session, region)
        self.service = AutoScalingService(session, region)

    def execute(self, region=None) -> list[ComplianceResult]:
        """Execute the autoscaling_group_capacity_rebalance_enabled check"""
        results = []
        
        if not region:
            region = self.region or 'us-east-1'
        
        groups = self.service.get_all_groups(region)
        
        for group in groups:
            # Only check groups with load balancers and target groups
            if group.load_balancers and group.target_groups:
                if group.capacity_rebalance:
                    status = "PASS"
                    message = f"Autoscaling group {group.name} has capacity rebalance enabled."
                else:
                    status = "FAIL"
                    message = f"Autoscaling group {group.name} does not have capacity rebalance enabled."

                results.append(ComplianceResult(
                    resource_id=group.arn,
                    resource_name=group.name,
                    status=status,
                    message=message,
                    region=group.region,
                    service="autoscaling",
                    check_name="autoscaling_group_capacity_rebalance_enabled"
                ))

        return results

"""
Auto Scaling Group ELB Health Check Enabled Check

Check if Auto Scaling groups have ELB health checks enabled.
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from base import BaseCheck, ComplianceResult

from ..autoscaling_service import AutoScalingService


class autoscaling_group_elb_health_check_enabled(BaseCheck):
    """Check if Auto Scaling groups have ELB health checks enabled"""

    def __init__(self, session=None, region=None):
        super().__init__(session, region)
        self.service = AutoScalingService(session, region)

    def execute(self, region=None) -> list[ComplianceResult]:
        """Execute the autoscaling_group_elb_health_check_enabled check"""
        results = []
        
        if not region:
            region = self.region or 'us-east-1'
        
        groups = self.service.get_all_groups(region)
        
        for group in groups:
            # Only check groups with load balancers and target groups
            if group.load_balancers and group.target_groups:
                if "ELB" in group.health_check_type:
                    status = "PASS"
                    message = f"Autoscaling group {group.name} has ELB health checks enabled."
                else:
                    status = "FAIL"
                    message = f"Autoscaling group {group.name} is associated with a load balancer but does not have ELB health checks enabled, instead it has {group.health_check_type} health checks."

                results.append(ComplianceResult(
                    resource_id=group.arn,
                    resource_name=group.name,
                    status=status,
                    message=message,
                    region=group.region,
                    service="autoscaling",
                    check_name="autoscaling_group_elb_health_check_enabled"
                ))

        return results

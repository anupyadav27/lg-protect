"""
Auto Scaling Group Launch Configuration Requires IMDSv2 Check

Check if Auto Scaling groups have launch configurations requiring IMDSv2.
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from base import BaseCheck, ComplianceResult

from ..autoscaling_service import AutoScalingService


class autoscaling_group_launch_configuration_requires_imdsv2(BaseCheck):
    """Check if Auto Scaling groups have launch configurations requiring IMDSv2"""

    def __init__(self, session=None, region=None):
        super().__init__(session, region)
        self.service = AutoScalingService(session, region)

    def execute(self, region=None) -> list[ComplianceResult]:
        """Execute the autoscaling_group_launch_configuration_requires_imdsv2 check"""
        results = []
        
        if not region:
            region = self.region or 'us-east-1'
        
        groups = self.service.get_all_groups(region)
        launch_configurations = self.service.get_all_launch_configurations(region)
        
        # Create a lookup for launch configurations
        lc_lookup = {lc.name: lc for lc in launch_configurations}
        
        for group in groups:
            if group.launch_configuration_name and group.launch_configuration_name in lc_lookup:
                lc = lc_lookup[group.launch_configuration_name]
                
                if lc.http_endpoint == "enabled" and lc.http_tokens == "required":
                    status = "PASS"
                    message = f"Autoscaling group {group.name} has IMDSv2 enabled and required."
                elif lc.http_endpoint == "disabled":
                    status = "PASS"
                    message = f"Autoscaling group {group.name} has metadata service disabled."
                else:
                    status = "FAIL"
                    message = f"Autoscaling group {group.name} has IMDSv2 disabled or not required."

                results.append(ComplianceResult(
                    resource_id=group.arn,
                    resource_name=group.name,
                    status=status,
                    message=message,
                    region=group.region,
                    service="autoscaling",
                    check_name="autoscaling_group_launch_configuration_requires_imdsv2"
                ))

        return results

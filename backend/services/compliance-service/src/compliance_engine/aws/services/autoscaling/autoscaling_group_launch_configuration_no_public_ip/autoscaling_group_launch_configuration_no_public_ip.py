"""
Auto Scaling Group Launch Configuration No Public IP Check

Check if Auto Scaling groups have launch configurations without public IP assignment.
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from base import BaseCheck, ComplianceResult

from ..autoscaling_service import AutoScalingService


class autoscaling_group_launch_configuration_no_public_ip(BaseCheck):
    """Check if Auto Scaling groups have launch configurations without public IP assignment"""

    def __init__(self, session=None, region=None):
        super().__init__(session, region)
        self.service = AutoScalingService(session, region)

    def execute(self, region=None) -> list[ComplianceResult]:
        """Execute the autoscaling_group_launch_configuration_no_public_ip check"""
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
                
                if lc.public_ip:
                    status = "FAIL"
                    message = f"Autoscaling group {group.name} has an associated launch configuration assigning a public IP address."
                else:
                    status = "PASS"
                    message = f"Autoscaling group {group.name} does not have an associated launch configuration assigning a public IP address."

                results.append(ComplianceResult(
                    resource_id=group.arn,
                    resource_name=group.name,
                    status=status,
                    message=message,
                    region=group.region,
                    service="autoscaling",
                    check_name="autoscaling_group_launch_configuration_no_public_ip"
                ))

        return results

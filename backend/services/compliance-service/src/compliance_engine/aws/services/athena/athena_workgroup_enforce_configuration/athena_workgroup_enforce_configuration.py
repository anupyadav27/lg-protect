"""
Athena WorkGroup Enforce Configuration Check

Check if Athena workgroups enforce their configuration.
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from base import BaseCheck, ComplianceResult

from ..athena_service import AthenaService


class athena_workgroup_enforce_configuration(BaseCheck):
    """Check if there are Athena workgroups not enforcing configuration"""

    def __init__(self, session=None, region=None):
        super().__init__(session, region)
        self.service = AthenaService(session, region)

    def execute(self, region=None) -> list[ComplianceResult]:
        """Execute the athena_workgroup_enforce_configuration check"""
        results = []
        
        if not region:
            region = self.region or 'us-east-1'
        
        workgroups = self.service.get_all_workgroups(region)
        
        for workgroup in workgroups:
            # Only check for enabled and used workgroups (has recent queries)
            if workgroup.state == "ENABLED" and workgroup.queries:
                if workgroup.enforce_workgroup_configuration:
                    status = "PASS"
                    message = f"Athena WorkGroup {workgroup.name} enforces the workgroup configuration, so it cannot be overridden by the client-side settings."
                else:
                    status = "FAIL"
                    message = f"Athena WorkGroup {workgroup.name} does not enforce the workgroup configuration, so it can be overridden by the client-side settings."

                results.append(ComplianceResult(
                    resource_id=workgroup.arn,
                    resource_name=workgroup.name,
                    status=status,
                    message=message,
                    region=workgroup.region,
                    service="athena",
                    check_name="athena_workgroup_enforce_configuration"
                ))

        return results

"""
Athena WorkGroup Logging Enabled Check

Check if Athena workgroups have CloudWatch logging enabled.
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from base import BaseCheck, ComplianceResult

from ..athena_service import AthenaService


class athena_workgroup_logging_enabled(BaseCheck):
    """Check if there are Athena workgroups with logging disabled."""

    def __init__(self, session=None, region=None):
        super().__init__(session, region)
        self.service = AthenaService(session, region)

    def execute(self, region=None) -> list[ComplianceResult]:
        """Execute the Athena workgroup logging enabled check.

        Iterates over all Athena workgroups and checks if is publishing logs to CloudWatch.

        Returns:
            List of compliance results for each workgroup.
        """
        results = []
        
        if not region:
            region = self.region or 'us-east-1'
        
        workgroups = self.service.get_all_workgroups(region)
        
        for workgroup in workgroups:
            # Only check for enabled and used workgroups (has recent queries)
            if workgroup.state == "ENABLED" and workgroup.queries:
                if workgroup.cloudwatch_logging:
                    status = "PASS"
                    message = f"Athena WorkGroup {workgroup.name} has CloudWatch logging enabled."
                else:
                    status = "FAIL"
                    message = f"Athena WorkGroup {workgroup.name} does not have CloudWatch logging enabled."

                results.append(ComplianceResult(
                    resource_id=workgroup.arn,
                    resource_name=workgroup.name,
                    status=status,
                    message=message,
                    region=workgroup.region,
                    service="athena",
                    check_name="athena_workgroup_logging_enabled"
                ))

        return results

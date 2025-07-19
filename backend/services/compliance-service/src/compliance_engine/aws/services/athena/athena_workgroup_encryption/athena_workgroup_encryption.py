"""
Athena WorkGroup Encryption Check

Check if Athena workgroups are encrypting query results.
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from base import BaseCheck, ComplianceResult

from ..athena_service import AthenaService


class athena_workgroup_encryption(BaseCheck):
    """Check if there are Athena workgroups not encrypting query results"""

    def __init__(self, session=None, region=None):
        super().__init__(session, region)
        self.service = AthenaService(session, region)

    def execute(self, region=None) -> list[ComplianceResult]:
        """Execute the athena_workgroup_encryption check"""
        results = []
        
        if not region:
            region = self.region or 'us-east-1'
        
        workgroups = self.service.get_all_workgroups(region)
        
        for workgroup in workgroups:
            # Only check for enabled and used workgroups (has recent queries)
            if workgroup.state == "ENABLED" and workgroup.queries:
                if workgroup.encryption_configuration.encrypted:
                    status = "PASS"
                    message = f"Athena WorkGroup {workgroup.name} encrypts the query results using {workgroup.encryption_configuration.encryption_option}."
                else:
                    status = "FAIL"
                    message = f"Athena WorkGroup {workgroup.name} does not encrypt the query results."

                results.append(ComplianceResult(
                    resource_id=workgroup.arn,
                    resource_name=workgroup.name,
                    status=status,
                    message=message,
                    region=workgroup.region,
                    service="athena",
                    check_name="athena_workgroup_encryption"
                ))

        return results

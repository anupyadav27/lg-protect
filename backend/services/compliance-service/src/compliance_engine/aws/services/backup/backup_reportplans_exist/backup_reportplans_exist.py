"""
AWS Backup Compliance Check

Check: backup_reportplans_exist
"""

import logging
from typing import List

# Import the base check class
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from base import BaseCheck, ComplianceResult
from ..backup_service import BackupService

logger = logging.getLogger(__name__)


class backup_reportplans_exist(BaseCheck):
    """Check: backup_reportplans_exist"""
    
    def __init__(self, session=None, region=None):
        super().__init__(session, region)
        self.service = BackupService(session, region)
    
    def execute(self, region=None) -> List[ComplianceResult]:
        """Execute the compliance check"""
        results = []
        
        try:
            backup_plans = self.service.get_all_backup_plans(region)
            backup_report_plans = self.service.get_all_backup_report_plans(region)
            
            # We only check report plans if backup plans exist
            if backup_plans:
                if backup_report_plans:
                    # At least one backup report plan exists
                    for report_plan in backup_report_plans:
                        results.append(ComplianceResult(
                            resource_id=report_plan.arn,
                            resource_name=report_plan.name,
                            status="PASS",
                            message=f"At least one backup report plan exists: {report_plan.name}.",
                            region=report_plan.region,
                            service=self.service._get_service_name(),
                            check_name=self.__class__.__name__
                        ))
                else:
                    # No backup report plans exist
                    results.append(ComplianceResult(
                        resource_id="backup-report-plans",
                        resource_name="Backup Report Plans",
                        status="FAIL",
                        message="No Backup Report Plan exist.",
                        region=region or self.region or 'us-east-1',
                        service=self.service._get_service_name(),
                        check_name=self.__class__.__name__
                    ))
        
        except Exception as e:
            logger.error(f"Error executing backup_reportplans_exist check: {e}")
            results.append(ComplianceResult(
                resource_id="backup-report-plans",
                resource_name="Backup Report Plans",
                status="ERROR",
                message=f"Error checking backup report plans: {e}",
                region=region or self.region or 'us-east-1',
                service=self.service._get_service_name(),
                check_name=self.__class__.__name__
            ))
        
        return results

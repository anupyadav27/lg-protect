"""
AWS Backup Compliance Check

Check: backup_plans_exist
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


class backup_plans_exist(BaseCheck):
    """Check: backup_plans_exist"""
    
    def __init__(self, session=None, region=None):
        super().__init__(session, region)
        self.service = BackupService(session, region)
    
    def execute(self, region=None) -> List[ComplianceResult]:
        """Execute the compliance check"""
        results = []
        
        try:
            backup_plans = self.service.get_all_backup_plans(region)
            backup_vaults = self.service.get_all_backup_vaults(region)
            
            if backup_plans:
                # At least one backup plan exists
                for plan in backup_plans:
                    results.append(ComplianceResult(
                        resource_id=plan.arn,
                        resource_name=plan.name,
                        status="PASS",
                        message=f"At least one Backup Plan exists: {plan.name}.",
                        region=plan.region,
                        service=self.service._get_service_name(),
                        check_name=self.__class__.__name__
                    ))
            elif backup_vaults:
                # No backup plans exist but vaults exist
                results.append(ComplianceResult(
                    resource_id="backup-plans",
                    resource_name="Backup Plans",
                    status="FAIL",
                    message="No Backup Plan exist.",
                    region=region or self.region or 'us-east-1',
                    service=self.service._get_service_name(),
                    check_name=self.__class__.__name__
                ))
            else:
                # No backup plans or vaults exist
                results.append(ComplianceResult(
                    resource_id="backup-plans",
                    resource_name="Backup Plans",
                    status="FAIL",
                    message="No Backup Plan exist.",
                    region=region or self.region or 'us-east-1',
                    service=self.service._get_service_name(),
                    check_name=self.__class__.__name__
                ))
        
        except Exception as e:
            logger.error(f"Error executing backup_plans_exist check: {e}")
            results.append(ComplianceResult(
                resource_id="backup-plans",
                resource_name="Backup Plans",
                status="ERROR",
                message=f"Error checking backup plans: {e}",
                region=region or self.region or 'us-east-1',
                service=self.service._get_service_name(),
                check_name=self.__class__.__name__
            ))
        
        return results

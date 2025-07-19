"""
AWS Backup Compliance Check

Check: backup_vaults_exist
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


class backup_vaults_exist(BaseCheck):
    """Check: backup_vaults_exist"""
    
    def __init__(self, session=None, region=None):
        super().__init__(session, region)
        self.service = BackupService(session, region)
    
    def execute(self, region=None) -> List[ComplianceResult]:
        """Execute the compliance check"""
        results = []
        
        try:
            backup_vaults = self.service.get_all_backup_vaults(region)
            
            if not backup_vaults:
                # No backup vaults exist
                results.append(ComplianceResult(
                    resource_id="backup-vaults",
                    resource_name="Backup Vaults",
                    status="FAIL",
                    message="No Backup Vault exist.",
                    region=region or self.region or 'us-east-1',
                    service=self.service._get_service_name(),
                    check_name=self.__class__.__name__
                ))
            else:
                # At least one backup vault exists
                for vault in backup_vaults:
                    results.append(ComplianceResult(
                        resource_id=vault.arn,
                        resource_name=vault.name,
                        status="PASS",
                        message=f"At least one backup vault exists: {vault.name}.",
                        region=vault.region,
                        service=self.service._get_service_name(),
                        check_name=self.__class__.__name__
                    ))
        
        except Exception as e:
            logger.error(f"Error executing backup_vaults_exist check: {e}")
            results.append(ComplianceResult(
                resource_id="backup-vaults",
                resource_name="Backup Vaults",
                status="ERROR",
                message=f"Error checking backup vaults: {e}",
                region=region or self.region or 'us-east-1',
                service=self.service._get_service_name(),
                check_name=self.__class__.__name__
            ))
        
        return results

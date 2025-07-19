"""
AWS Backup Compliance Check

Check: backup_vaults_encrypted
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


class backup_vaults_encrypted(BaseCheck):
    """Check: backup_vaults_encrypted"""
    
    def __init__(self, session=None, region=None):
        super().__init__(session, region)
        self.service = BackupService(session, region)
    
    def execute(self, region=None) -> List[ComplianceResult]:
        """Execute the compliance check"""
        results = []
        
        try:
            backup_vaults = self.service.get_all_backup_vaults(region)
            
            for vault in backup_vaults:
                if vault.encryption:
                    status = "PASS"
                    message = f"Backup Vault {vault.name} is encrypted at rest."
                else:
                    status = "FAIL"
                    message = f"Backup Vault {vault.name} is not encrypted at rest."
                
                results.append(ComplianceResult(
                    resource_id=vault.arn,
                    resource_name=vault.name,
                    status=status,
                    message=message,
                    region=vault.region,
                    service=self.service._get_service_name(),
                    check_name=self.__class__.__name__
                ))
        
        except Exception as e:
            logger.error(f"Error executing backup_vaults_encrypted check: {e}")
            results.append(ComplianceResult(
                resource_id="backup-vaults",
                resource_name="Backup Vaults",
                status="ERROR",
                message=f"Error checking backup vault encryption: {e}",
                region=region or self.region or 'us-east-1',
                service=self.service._get_service_name(),
                check_name=self.__class__.__name__
            ))
        
        return results

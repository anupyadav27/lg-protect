"""
AWS Backup Compliance Check

Check: backup_recovery_point_encrypted
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


class backup_recovery_point_encrypted(BaseCheck):
    """Check: backup_recovery_point_encrypted"""
    
    def __init__(self, session=None, region=None):
        super().__init__(session, region)
        self.service = BackupService(session, region)
    
    def execute(self, region=None) -> List[ComplianceResult]:
        """Execute the compliance check"""
        results = []
        
        try:
            recovery_points = self.service.get_all_recovery_points(region)
            
            for point in recovery_points:
                if point.encrypted:
                    status = "PASS"
                    message = f"Backup Recovery Point {point.id} for Backup Vault {point.backup_vault_name} is encrypted at rest."
                else:
                    status = "FAIL"
                    message = f"Backup Recovery Point {point.id} for Backup Vault {point.backup_vault_name} is not encrypted at rest."
                
                results.append(ComplianceResult(
                    resource_id=point.arn,
                    resource_name=point.id,
                    status=status,
                    message=message,
                    region=point.region,
                    service=self.service._get_service_name(),
                    check_name=self.__class__.__name__
                ))
        
        except Exception as e:
            logger.error(f"Error executing backup_recovery_point_encrypted check: {e}")
            results.append(ComplianceResult(
                resource_id="recovery-points",
                resource_name="Recovery Points",
                status="ERROR",
                message=f"Error checking recovery point encryption: {e}",
                region=region or self.region or 'us-east-1',
                service=self.service._get_service_name(),
                check_name=self.__class__.__name__
            ))
        
        return results

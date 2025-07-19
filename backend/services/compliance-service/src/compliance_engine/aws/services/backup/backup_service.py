"""
AWS Backup Service

Service abstraction for AWS Backup compliance checks.
"""

import boto3
import logging
from typing import Optional, Dict, List, Any
from datetime import datetime
from pydantic import BaseModel

# Import the base service class
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from base import BaseService, ComplianceResult

logger = logging.getLogger(__name__)


class BackupVault(BaseModel):
    """Backup vault model"""
    arn: str
    name: str
    region: str
    encryption: Optional[str]
    recovery_points: int
    locked: bool
    min_retention_days: Optional[int] = None
    max_retention_days: Optional[int] = None
    tags: Optional[List[Dict[str, str]]] = []


class BackupPlan(BaseModel):
    """Backup plan model"""
    arn: str
    id: str
    region: str
    name: str
    version_id: str
    last_execution_date: Optional[datetime]
    advanced_settings: List[Dict[str, Any]]
    tags: Optional[List[Dict[str, str]]] = []


class BackupReportPlan(BaseModel):
    """Backup report plan model"""
    arn: str
    region: str
    name: str
    last_attempted_execution_date: Optional[datetime]
    last_successful_execution_date: Optional[datetime]


class RecoveryPoint(BaseModel):
    """Recovery point model"""
    arn: str
    id: str
    region: str
    backup_vault_name: str
    encrypted: bool
    backup_vault_region: str
    tags: Optional[List[Dict[str, str]]] = []


class BackupService(BaseService):
    """AWS Backup service for compliance checks"""
    
    def __init__(self, session: boto3.Session = None, region: str = None):
        super().__init__(session, region)
        self.backup_vaults: Dict[str, List[BackupVault]] = {}
        self.backup_plans: Dict[str, List[BackupPlan]] = {}
        self.backup_report_plans: Dict[str, List[BackupReportPlan]] = {}
        self.recovery_points: Dict[str, List[RecoveryPoint]] = {}
    
    def _get_service_name(self) -> str:
        return "backup"
    
    def _load_resources_for_region(self, region: str) -> None:
        """Load Backup resources for the specified region"""
        try:
            client = self._get_client(region)
            
            # Load backup vaults
            self.backup_vaults[region] = self._get_backup_vaults(client, region)
            
            # Load backup plans
            self.backup_plans[region] = self._get_backup_plans(client, region)
            
            # Load backup report plans
            self.backup_report_plans[region] = self._get_backup_report_plans(client, region)
            
            # Load recovery points
            self.recovery_points[region] = self._get_recovery_points(client, region)
            
        except Exception as e:
            logger.error(f"Error loading backup resources for region {region}: {e}")
    
    def _get_backup_vaults(self, client, region: str) -> List[BackupVault]:
        """Get all backup vaults for the region"""
        vaults = []
        try:
            paginator = client.get_paginator("list_backup_vaults")
            for page in paginator.paginate():
                for vault in page.get("BackupVaultList", []):
                    vaults.append(BackupVault(
                        arn=vault.get("BackupVaultArn"),
                        name=vault.get("BackupVaultName"),
                        region=region,
                        encryption=vault.get("EncryptionKeyArn"),
                        recovery_points=vault.get("NumberOfRecoveryPoints", 0),
                        locked=vault.get("Locked", False),
                        min_retention_days=vault.get("MinRetentionDays"),
                        max_retention_days=vault.get("MaxRetentionDays")
                    ))
        except Exception as e:
            logger.error(f"Error getting backup vaults for region {region}: {e}")
        
        return vaults
    
    def _get_backup_plans(self, client, region: str) -> List[BackupPlan]:
        """Get all backup plans for the region"""
        plans = []
        try:
            paginator = client.get_paginator("list_backup_plans")
            for page in paginator.paginate():
                for plan in page.get("BackupPlansList", []):
                    plans.append(BackupPlan(
                        arn=plan.get("BackupPlanArn"),
                        id=plan.get("BackupPlanId"),
                        region=region,
                        name=plan.get("BackupPlanName"),
                        version_id=plan.get("VersionId"),
                        last_execution_date=plan.get("LastExecutionDate"),
                        advanced_settings=plan.get("AdvancedBackupSettings", [])
                    ))
        except Exception as e:
            logger.error(f"Error getting backup plans for region {region}: {e}")
        
        return plans
    
    def _get_backup_report_plans(self, client, region: str) -> List[BackupReportPlan]:
        """Get all backup report plans for the region"""
        report_plans = []
        try:
            response = client.list_report_plans()
            for plan in response.get("ReportPlans", []):
                report_plans.append(BackupReportPlan(
                    arn=plan.get("ReportPlanArn"),
                    region=region,
                    name=plan.get("ReportPlanName"),
                    last_attempted_execution_date=plan.get("LastAttemptedExecutionTime"),
                    last_successful_execution_date=plan.get("LastSuccessfulExecutionTime")
                ))
        except Exception as e:
            logger.error(f"Error getting backup report plans for region {region}: {e}")
        
        return report_plans
    
    def _get_recovery_points(self, client, region: str) -> List[RecoveryPoint]:
        """Get all recovery points for the region"""
        recovery_points = []
        try:
            # Get recovery points from all vaults
            for vault in self.backup_vaults.get(region, []):
                paginator = client.get_paginator("list_recovery_points_by_backup_vault")
                for page in paginator.paginate(BackupVaultName=vault.name):
                    for point in page.get("RecoveryPoints", []):
                        recovery_points.append(RecoveryPoint(
                            arn=point.get("RecoveryPointArn"),
                            id=point.get("RecoveryPointArn").split("/")[-1],
                            region=region,
                            backup_vault_name=vault.name,
                            encrypted=point.get("IsEncrypted", False),
                            backup_vault_region=region
                        ))
        except Exception as e:
            logger.error(f"Error getting recovery points for region {region}: {e}")
        
        return recovery_points
    
    def get_all_backup_vaults(self, region: str = None) -> List[BackupVault]:
        """Get all backup vaults for the specified region"""
        if not region:
            region = self.region or 'us-east-1'
        
        if region not in self.backup_vaults:
            self._load_resources_for_region(region)
        
        return self.backup_vaults.get(region, [])
    
    def get_all_backup_plans(self, region: str = None) -> List[BackupPlan]:
        """Get all backup plans for the specified region"""
        if not region:
            region = self.region or 'us-east-1'
        
        if region not in self.backup_plans:
            self._load_resources_for_region(region)
        
        return self.backup_plans.get(region, [])
    
    def get_all_backup_report_plans(self, region: str = None) -> List[BackupReportPlan]:
        """Get all backup report plans for the specified region"""
        if not region:
            region = self.region or 'us-east-1'
        
        if region not in self.backup_report_plans:
            self._load_resources_for_region(region)
        
        return self.backup_report_plans.get(region, [])
    
    def get_all_recovery_points(self, region: str = None) -> List[RecoveryPoint]:
        """Get all recovery points for the specified region"""
        if not region:
            region = self.region or 'us-east-1'
        
        if region not in self.recovery_points:
            self._load_resources_for_region(region)
        
        return self.recovery_points.get(region, [])

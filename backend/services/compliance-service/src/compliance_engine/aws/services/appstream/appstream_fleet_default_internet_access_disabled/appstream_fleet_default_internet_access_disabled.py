"""
AppStream Fleet Default Internet Access Disabled Check

Ensures AppStream fleets have default internet access disabled.
"""

import boto3
from typing import List
from datetime import datetime

# Import base check and reporting
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from base import BaseCheck, ComplianceResult
from utils.reports.reporting import create_compliance_report

# Import service
from ..appstream_service import AppStreamService


class appstream_fleet_default_internet_access_disabled(BaseCheck):
    """Check if AppStream fleets have default internet access disabled"""
    
    def __init__(self):
        super().__init__()
        self.check_name = "appstream_fleet_default_internet_access_disabled"
        self.description = "Ensure AppStream fleets have default internet access disabled"
        self.severity = "MEDIUM"
        self.category = "Network Security"
    
    def execute(self, region: str = None) -> List[ComplianceResult]:
        """Execute the compliance check"""
        results = []
        
        try:
            # Initialize service
            session = boto3.Session()
            service = AppStreamService(session, region)
            
            # Get all fleets
            fleets = service.get_all_fleets(region)
            
            for fleet in fleets:
                result = ComplianceResult(
                    resource_id=fleet.arn,
                    resource_name=fleet.name,
                    resource_type="AppStream Fleet",
                    region=fleet.region,
                    check_name=self.check_name,
                    status="PASS",
                    message=f"Fleet {fleet.name} has default internet access disabled.",
                    timestamp=datetime.utcnow()
                )
                
                if fleet.enable_default_internet_access:
                    result.status = "FAIL"
                    result.message = f"Fleet {fleet.name} has default internet access enabled."
                
                results.append(result)
                
        except Exception as e:
            # Handle errors
            result = ComplianceResult(
                resource_id="",
                resource_name="",
                resource_type="AppStream Fleet",
                region=region or "unknown",
                check_name=self.check_name,
                status="ERROR",
                message=f"Error checking AppStream fleet default internet access: {str(e)}",
                timestamp=datetime.utcnow()
            )
            results.append(result)
        
        return results

"""
AppStream Fleet Maximum Session Duration Check

Ensures AppStream fleets have maximum session duration no longer than 10 hours.
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


class appstream_fleet_maximum_session_duration(BaseCheck):
    """Check if AppStream fleets have maximum session duration no longer than 10 hours"""
    
    def __init__(self):
        super().__init__()
        self.check_name = "appstream_fleet_maximum_session_duration"
        self.description = "Ensure AppStream fleets have maximum session duration no longer than 10 hours"
        self.severity = "MEDIUM"
        self.category = "Session Management"
    
    def execute(self, region: str = None) -> List[ComplianceResult]:
        """Execute the compliance check"""
        results = []
        
        # max_session_duration_seconds, default: 36000 seconds (10 hours)
        max_session_duration_seconds = 36000
        
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
                    message=f"Fleet {fleet.name} has the maximum session duration configured for less than 10 hours.",
                    timestamp=datetime.utcnow()
                )
                
                if fleet.max_user_duration_in_seconds >= max_session_duration_seconds:
                    result.status = "FAIL"
                    result.message = f"Fleet {fleet.name} has the maximum session duration configured for more than 10 hours."
                
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
                message=f"Error checking AppStream fleet maximum session duration: {str(e)}",
                timestamp=datetime.utcnow()
            )
            results.append(result)
        
        return results

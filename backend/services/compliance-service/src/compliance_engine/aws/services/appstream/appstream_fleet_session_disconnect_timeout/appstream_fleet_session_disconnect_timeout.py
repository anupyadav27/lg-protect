"""
AppStream Fleet Session Disconnect Timeout Check

Ensures AppStream fleets have session disconnect timeout set to 5 minutes or less.
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


class appstream_fleet_session_disconnect_timeout(BaseCheck):
    """Check if AppStream fleets have session disconnect timeout set to 5 minutes or less"""
    
    def __init__(self):
        super().__init__()
        self.check_name = "appstream_fleet_session_disconnect_timeout"
        self.description = "Ensure AppStream fleets have session disconnect timeout set to 5 minutes or less"
        self.severity = "MEDIUM"
        self.category = "Session Management"
    
    def execute(self, region: str = None) -> List[ComplianceResult]:
        """Execute the compliance check"""
        results = []
        
        # max_disconnect_timeout_in_seconds, default: 300 seconds (5 minutes)
        max_disconnect_timeout_in_seconds = 300
        
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
                    message=f"Fleet {fleet.name} has the session disconnect timeout set to less than 5 minutes.",
                    timestamp=datetime.utcnow()
                )
                
                if fleet.disconnect_timeout_in_seconds > max_disconnect_timeout_in_seconds:
                    result.status = "FAIL"
                    result.message = f"Fleet {fleet.name} has the session disconnect timeout set to more than 5 minutes."
                
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
                message=f"Error checking AppStream fleet session disconnect timeout: {str(e)}",
                timestamp=datetime.utcnow()
            )
            results.append(result)
        
        return results

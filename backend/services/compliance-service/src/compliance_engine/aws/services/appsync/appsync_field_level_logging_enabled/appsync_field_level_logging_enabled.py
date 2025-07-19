"""
AppSync Field Level Logging Enabled Check

Ensures AppSync GraphQL APIs have field-level logging enabled.
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
from ..appsync_service import AppSyncService


class appsync_field_level_logging_enabled(BaseCheck):
    """Check if AppSync GraphQL APIs have field-level logging enabled"""
    
    def __init__(self):
        super().__init__()
        self.check_name = "appsync_field_level_logging_enabled"
        self.description = "Ensure AppSync GraphQL APIs have field-level logging enabled"
        self.severity = "MEDIUM"
        self.category = "Logging"
    
    def execute(self, region: str = None) -> List[ComplianceResult]:
        """Execute the compliance check"""
        results = []
        
        try:
            # Initialize service
            session = boto3.Session()
            service = AppSyncService(session, region)
            
            # Get all APIs
            apis = service.get_all_apis(region)
            
            for api in apis:
                result = ComplianceResult(
                    resource_id=api.arn,
                    resource_name=api.name,
                    resource_type="AppSync GraphQL API",
                    region=api.region,
                    check_name=self.check_name,
                    status="PASS",
                    message=f"AppSync API {api.name} has field log level enabled.",
                    timestamp=datetime.utcnow()
                )
                
                if api.field_log_level not in ["ALL", "ERROR"]:
                    result.status = "FAIL"
                    result.message = f"AppSync API {api.name} does not have field log level enabled."
                
                results.append(result)
                
        except Exception as e:
            # Handle errors
            result = ComplianceResult(
                resource_id="",
                resource_name="",
                resource_type="AppSync GraphQL API",
                region=region or "unknown",
                check_name=self.check_name,
                status="ERROR",
                message=f"Error checking AppSync field level logging: {str(e)}",
                timestamp=datetime.utcnow()
            )
            results.append(result)
        
        return results

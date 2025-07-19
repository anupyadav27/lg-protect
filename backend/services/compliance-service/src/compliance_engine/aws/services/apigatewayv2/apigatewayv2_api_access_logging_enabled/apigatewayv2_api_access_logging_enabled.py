"""
API Gateway v2 API Access Logging Enabled Check

Ensures API Gateway v2 APIs have access logging enabled.
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
from ..apigatewayv2_service import APIGatewayV2Service


class apigatewayv2_api_access_logging_enabled(BaseCheck):
    """Check if API Gateway v2 APIs have access logging enabled"""
    
    def __init__(self):
        super().__init__()
        self.check_name = "apigatewayv2_api_access_logging_enabled"
        self.description = "Ensure API Gateway v2 APIs have access logging enabled"
        self.severity = "MEDIUM"
        self.category = "Logging"
    
    def execute(self, region: str = None) -> List[ComplianceResult]:
        """Execute the compliance check"""
        results = []
        
        try:
            # Initialize service
            session = boto3.Session()
            service = APIGatewayV2Service(session, region)
            
            # Get all stages (which contain access log settings)
            stages = service.get_all_stages(region)
            
            for stage in stages:
                result = ComplianceResult(
                    resource_id=stage.arn,
                    resource_name=f"{stage.name} (API: {stage.api_id})",
                    resource_type="API Gateway v2 Stage",
                    region=stage.region,
                    check_name=self.check_name,
                    status="FAIL",
                    message=f"API Gateway v2 stage {stage.name} does not have access logging enabled.",
                    timestamp=datetime.utcnow()
                )
                
                if stage.access_log_settings:
                    result.status = "PASS"
                    result.message = f"API Gateway v2 stage {stage.name} has access logging enabled."
                
                results.append(result)
                
        except Exception as e:
            # Handle errors
            result = ComplianceResult(
                resource_id="",
                resource_name="",
                resource_type="API Gateway v2 Stage",
                region=region or "unknown",
                check_name=self.check_name,
                status="ERROR",
                message=f"Error checking API Gateway v2 access logging: {str(e)}",
                timestamp=datetime.utcnow()
            )
            results.append(result)
        
        return results

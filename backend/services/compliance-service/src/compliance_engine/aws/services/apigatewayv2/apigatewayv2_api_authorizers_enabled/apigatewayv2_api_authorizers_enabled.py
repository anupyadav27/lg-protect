"""
API Gateway v2 API Authorizers Enabled Check

Ensures API Gateway v2 APIs have authorizers enabled.
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


class apigatewayv2_api_authorizers_enabled(BaseCheck):
    """Check if API Gateway v2 APIs have authorizers enabled"""
    
    def __init__(self):
        super().__init__()
        self.check_name = "apigatewayv2_api_authorizers_enabled"
        self.description = "Ensure API Gateway v2 APIs have authorizers enabled"
        self.severity = "HIGH"
        self.category = "Authentication"
    
    def execute(self, region: str = None) -> List[ComplianceResult]:
        """Execute the compliance check"""
        results = []
        
        try:
            # Initialize service
            session = boto3.Session()
            service = APIGatewayV2Service(session, region)
            
            # Get all APIs
            apis = service.get_all_apis(region)
            
            for api in apis:
                result = ComplianceResult(
                    resource_id=api.arn,
                    resource_name=api.name,
                    resource_type="API Gateway v2 API",
                    region=api.region,
                    check_name=self.check_name,
                    status="FAIL",
                    message=f"API Gateway v2 API {api.name} does not have authorizers enabled.",
                    timestamp=datetime.utcnow()
                )
                
                # Check if API has any authorizers
                api_authorizers = [auth for auth in service.authorizers.values() if auth.api_id == api.id]
                if api_authorizers:
                    result.status = "PASS"
                    result.message = f"API Gateway v2 API {api.name} has {len(api_authorizers)} authorizer(s) enabled."
                
                results.append(result)
                
        except Exception as e:
            # Handle errors
            result = ComplianceResult(
                resource_id="",
                resource_name="",
                resource_type="API Gateway v2 API",
                region=region or "unknown",
                check_name=self.check_name,
                status="ERROR",
                message=f"Error checking API Gateway v2 authorizers: {str(e)}",
                timestamp=datetime.utcnow()
            )
            results.append(result)
        
        return results

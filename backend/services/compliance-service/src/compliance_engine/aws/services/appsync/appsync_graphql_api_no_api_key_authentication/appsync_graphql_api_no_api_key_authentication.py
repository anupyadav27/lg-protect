"""
AppSync GraphQL API No API Key Authentication Check

Ensures AppSync GraphQL APIs are not using API key authentication.
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


class appsync_graphql_api_no_api_key_authentication(BaseCheck):
    """Check if AppSync GraphQL APIs are not using API key authentication"""
    
    def __init__(self):
        super().__init__()
        self.check_name = "appsync_graphql_api_no_api_key_authentication"
        self.description = "Ensure AppSync GraphQL APIs are not using API key authentication"
        self.severity = "HIGH"
        self.category = "Authentication"
    
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
                if api.type == "GRAPHQL":
                    result = ComplianceResult(
                        resource_id=api.arn,
                        resource_name=api.name,
                        resource_type="AppSync GraphQL API",
                        region=api.region,
                        check_name=self.check_name,
                        status="PASS",
                        message=f"AppSync GraphQL API {api.name} is not using an API KEY for authentication.",
                        timestamp=datetime.utcnow()
                    )
                    
                    if api.authentication_type == "API_KEY":
                        result.status = "FAIL"
                        result.message = f"AppSync GraphQL API {api.name} is using an API KEY for authentication."
                    
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
                message=f"Error checking AppSync API key authentication: {str(e)}",
                timestamp=datetime.utcnow()
            )
            results.append(result)
        
        return results

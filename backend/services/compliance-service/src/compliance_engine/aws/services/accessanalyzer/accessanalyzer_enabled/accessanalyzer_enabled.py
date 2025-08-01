"""
AccessAnalyzer Enabled Compliance Check

Checks if IAM Access Analyzer is enabled in the AWS account.
"""

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..', 'utils'))
from reporting import (
    BaseCheck, CheckReport, CheckMetadata, CheckStatus, 
    Severity, ComplianceStandard
)

from ..accessanalyzer_client import get_accessanalyzer_client
from ..accessanalyzer_service import AccessAnalyzerService
import boto3


class accessanalyzer_enabled(BaseCheck):
    """Check if IAM Access Analyzer is enabled"""
    
    def _get_metadata(self) -> CheckMetadata:
        """Get check metadata"""
        return CheckMetadata(
            check_id="accessanalyzer_enabled",
            check_name="AccessAnalyzer Enabled",
            description="Check if IAM Access Analyzer is enabled in the AWS account",
            severity=Severity.LOW,
            compliance_standard=ComplianceStandard.AWS_FOUNDATIONAL_SECURITY_BEST_PRACTICES,
            category="Access Control",
            tags=["accessanalyzer", "iam", "security"],
            remediation="Enable IAM Access Analyzer for all accounts using AWS CLI: aws accessanalyzer create-analyzer --analyzer-name <NAME> --type <ACCOUNT|ORGANIZATION>",
            references=[
                "https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html",
                "https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-getting-started.html"
            ]
        )
    
    def execute(self) -> list[CheckReport]:
        """Execute the compliance check"""
        findings = []
        
        try:
            # Get service client
            client = get_accessanalyzer_client()
            
            # Create service instance to get analyzers
            session = boto3.Session()
            service = AccessAnalyzerService(session)
            analyzers = service.get_all_analyzers()
            
            # Check each analyzer
            for analyzer in analyzers:
                report = self._check_analyzer(analyzer)
                findings.append(report)
            
            # If no analyzers found, create a failure report
            if not analyzers:
                report = CheckReport(
                    status=CheckStatus.FAIL,
                    status_extended="IAM Access Analyzer is not enabled in the AWS account",
                    resource={"type": "accessanalyzer", "id": "unknown"},
                    metadata=self.metadata,
                    region="unknown",
                    evidence={
                        "resource_id": "unknown",
                        "resource_name": "unknown",
                        "status": "NOT_AVAILABLE"
                    }
                )
                findings.append(report)
                
        except Exception as e:
            # Create error report
            report = CheckReport(
                status=CheckStatus.ERROR,
                status_extended=f"Error checking AccessAnalyzer status: {str(e)}",
                resource={"type": "accessanalyzer", "id": "error"},
                metadata=self.metadata,
                region="unknown",
                evidence={
                    "error": str(e),
                    "resource_id": "error",
                    "resource_name": "error"
                }
            )
            findings.append(report)
        
        return findings
    
    def _check_analyzer(self, analyzer) -> CheckReport:
        """Check if a single analyzer is enabled"""
        
        # Determine status and message
        if analyzer.is_active:
            status = CheckStatus.PASS
            status_extended = f"IAM Access Analyzer {analyzer.name} is enabled and active."
        else:
            status = CheckStatus.FAIL
            if analyzer.status == "NOT_AVAILABLE":
                status_extended = "IAM Access Analyzer is not enabled in the AWS account."
            else:
                status_extended = f"IAM Access Analyzer {analyzer.name} is not active (status: {analyzer.status})."
        
        # Create report for this analyzer
        report = CheckReport(
            status=status,
            status_extended=status_extended,
            resource=analyzer.dict(),
            metadata=self.metadata,
            region=analyzer.region,
            evidence={
                "resource_id": analyzer.arn,
                "resource_name": analyzer.name,
                "status": analyzer.status,
                "type": analyzer.type,
                "region": analyzer.region
            }
        )
        
        return report

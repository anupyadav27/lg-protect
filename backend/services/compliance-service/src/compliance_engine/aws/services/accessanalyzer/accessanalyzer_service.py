"""
AccessAnalyzer Service

Service abstraction for AccessAnalyzer compliance checks.
"""

from datetime import datetime
from typing import Optional, Dict, List
from pydantic import BaseModel
import boto3
import logging

# Import the base service class
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from base import BaseService, ComplianceResult

logger = logging.getLogger(__name__)


class Finding(BaseModel):
    """AccessAnalyzer finding model"""
    id: str
    status: str = ""
    resource: Optional[str] = None
    resource_type: Optional[str] = None
    finding_type: Optional[str] = None
    issue_code: Optional[str] = None
    issue_details: Optional[Dict] = None


class Analyzer(BaseModel):
    """AccessAnalyzer analyzer model"""
    arn: str
    name: str
    status: str
    type: str
    region: str
    findings: List[Finding] = []
    tags: Optional[List[Dict]] = []
    
    # Computed properties
    @property
    def is_active(self) -> bool:
        """Check if analyzer is active"""
        return self.status == "ACTIVE"
    
    @property
    def active_findings_count(self) -> int:
        """Get count of active findings"""
        return len([f for f in self.findings if f.status == "ACTIVE"])


class AccessAnalyzerService(BaseService):
    """AccessAnalyzer service that collects resource data for compliance checks"""
    
    def __init__(self, session: boto3.Session = None, region: str = None):
        super().__init__(session, region)
        self.analyzers = []
    
    def _get_service_name(self) -> str:
        """Get the AWS service name"""
        return 'accessanalyzer'
    
    def get_all_analyzers(self, region: str = None) -> List[Analyzer]:
        """
        Get all AccessAnalyzer analyzers for the specified region
        
        Args:
            region: AWS region to scan (defaults to service region)
            
        Returns:
            List of Analyzer objects
        """
        if not region:
            region = self.region or 'us-east-1'
        
        # Clear existing analyzers for this region
        self.analyzers = [a for a in self.analyzers if a.region != region]
        
        # Load resources for this region
        self._load_resources_for_region(region)
        
        return [a for a in self.analyzers if a.region == region]
    
    def _load_resources_for_region(self, region: str):
        """Load all AccessAnalyzer resources from AWS for a specific region"""
        try:
            client = self.get_client(region)
            self._list_analyzers(client, region)
        except Exception as error:
            logger.error(f"AccessAnalyzer - Error getting resources from {region}: {error}")
    
    def _list_analyzers(self, client, region: str):
        """Get list of AccessAnalyzer analyzers from AWS"""
        logger.info(f"AccessAnalyzer - Getting analyzers from {region}")
        
        try:
            paginator = client.get_paginator('list_analyzers')
            for page in paginator.paginate():
                for analyzer_data in page.get('analyzers', []):
                    analyzer = self._create_analyzer(analyzer_data, region)
                    if analyzer:
                        # Load findings for active analyzers
                        if analyzer.is_active:
                            self._load_findings(client, analyzer)
                        self.analyzers.append(analyzer)
            
            # If no analyzers found, create a placeholder
            if not any(a.region == region for a in self.analyzers):
                placeholder_analyzer = Analyzer(
                    arn=f"arn:aws:access-analyzer:{region}:{self.account_id}:analyzer/unknown",
                    name="analyzer/unknown",
                    status="NOT_AVAILABLE",
                    type="",
                    region=region,
                    findings=[],
                    tags=[]
                )
                self.analyzers.append(placeholder_analyzer)
                    
        except Exception as error:
            logger.error(f"AccessAnalyzer - Error getting analyzers from {region}: {error}")
    
    def _create_analyzer(self, analyzer_data: Dict, region: str) -> Optional[Analyzer]:
        """Create analyzer object from AWS data"""
        try:
            return Analyzer(
                arn=analyzer_data.get('arn', ''),
                name=analyzer_data.get('name', ''),
                status=analyzer_data.get('status', ''),
                type=analyzer_data.get('type', ''),
                region=region,
                findings=[],
                tags=analyzer_data.get('tags', [])
            )
        except Exception as e:
            logger.error(f"Error creating analyzer object: {e}")
            return None
    
    def _load_findings(self, client, analyzer: Analyzer):
        """Load findings for an analyzer"""
        try:
            paginator = client.get_paginator('list_findings')
            for page in paginator.paginate(analyzerArn=analyzer.arn):
                for finding_data in page.get('findings', []):
                    finding = Finding(
                        id=finding_data.get('id', ''),
                        status=finding_data.get('status', ''),
                        resource=finding_data.get('resource', ''),
                        resource_type=finding_data.get('resourceType', ''),
                        finding_type=finding_data.get('findingType', ''),
                        issue_code=finding_data.get('issueCode', ''),
                        issue_details=finding_data.get('issueDetails', {})
                    )
                    analyzer.findings.append(finding)
        except Exception as e:
            logger.error(f"Error loading findings for analyzer {analyzer.name}: {e}")

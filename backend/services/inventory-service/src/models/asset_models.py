#!/usr/bin/env python3
"""
Asset Models for LG-Protect Inventory System

Enhanced data models for enterprise-grade inventory with security analysis,
compliance mapping, and relationship tracking.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional, Set
from enum import Enum
from datetime import datetime
import json

class AssetType(Enum):
    """Asset type classification"""
    COMPUTE = "compute"
    STORAGE = "storage"
    DATABASE = "database"
    NETWORK = "network"
    SECURITY = "security"
    IDENTITY = "identity"
    MONITORING = "monitoring"
    ANALYTICS = "analytics"
    APPLICATION = "application"
    OTHER = "other"

class RiskLevel(Enum):
    """Risk level classification"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

@dataclass
class AssetMetadata:
    """Enhanced metadata for assets"""
    discovery_method: str
    scope: str
    raw_data: Dict[str, Any] = field(default_factory=dict)
    additional_data: Dict[str, Any] = field(default_factory=dict)
    last_updated: datetime = field(default_factory=datetime.utcnow)
    
    def __post_init__(self):
        if not self.raw_data:
            self.raw_data = {}
        if not self.additional_data:
            self.additional_data = {}

@dataclass
class SecurityFinding:
    """Security finding for an asset"""
    finding_type: str
    severity: str
    title: str
    description: str
    resource_id: str
    compliance_frameworks: List[str] = field(default_factory=list)
    remediation: Optional[str] = None
    finding_id: Optional[str] = None
    created_at: Optional[datetime] = None
    
    def __post_init__(self):
        if not self.compliance_frameworks:
            self.compliance_frameworks = []
        if not self.finding_id:
            self.finding_id = f"{self.resource_id}_{self.finding_type}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        if not self.created_at:
            self.created_at = datetime.now()

@dataclass
class RiskScore:
    """Comprehensive risk scoring for assets"""
    overall_score: float
    category_scores: Dict[str, float] = field(default_factory=dict)
    risk_level: Optional[str] = None
    findings_count: int = 0
    critical_findings: int = 0
    high_findings: int = 0
    medium_findings: int = 0
    low_findings: int = 0
    calculated_at: Optional[str] = None
    threat_vectors: List[str] = field(default_factory=list)
    risk_factors: Dict[str, float] = field(default_factory=dict)
    
    def __post_init__(self):
        if not self.category_scores:
            self.category_scores = {}
        if not self.calculated_at:
            self.calculated_at = datetime.now().isoformat()
        if not self.threat_vectors:
            self.threat_vectors = []
        if not self.risk_factors:
            self.risk_factors = {}

@dataclass
class AssetInfo:
    """Enhanced asset information model for discovery engines"""
    service: str
    resource_type: str
    resource_id: str
    region: str
    name: Optional[str] = None
    arn: Optional[str] = None
    created_date: Optional[Any] = None
    tags: List[Dict[str, str]] = field(default_factory=list)
    configuration: Dict[str, Any] = field(default_factory=dict)
    security_findings: List[SecurityFinding] = field(default_factory=list)
    risk_score: Optional[RiskScore] = None
    
    def __post_init__(self):
        if not self.tags:
            self.tags = []
        if not self.configuration:
            self.configuration = {}
        if not self.security_findings:
            self.security_findings = []

@dataclass
class Asset:
    """Enhanced asset model with security and compliance features"""
    asset_id: str
    asset_type: AssetType
    service_name: str
    region: str
    name: str
    arn: Optional[str] = None
    tags: Dict[str, str] = field(default_factory=dict)
    metadata: Optional[AssetMetadata] = None
    
    # Security and compliance features
    security_findings: List[SecurityFinding] = field(default_factory=list)
    risk_score: int = 0  # 0-100
    compliance_status: Dict[str, str] = field(default_factory=dict)
    
    # Enhanced risk scoring
    enhanced_risk_score: Optional[RiskScore] = None
    
    # Relationships
    relationships: Dict[str, List[str]] = field(default_factory=dict)
    
    # Asset state
    state: str = "active"
    created_at: datetime = field(default_factory=datetime.utcnow)
    last_scan_at: Optional[datetime] = None
    
    def __post_init__(self):
        if not self.tags:
            self.tags = {}
        if not self.security_findings:
            self.security_findings = []
        if not self.compliance_status:
            self.compliance_status = {}
        if not self.relationships:
            self.relationships = {}
    
    def add_security_finding(self, finding: SecurityFinding) -> None:
        """Add a security finding to the asset"""
        self.security_findings.append(finding)
        self._update_risk_score()
    
    def _update_risk_score(self) -> None:
        """Update risk score based on security findings"""
        if not self.security_findings:
            self.risk_score = 0
            return
        
        risk_weights = {
            'critical': 25,
            'high': 15,
            'medium': 8,
            'low': 3,
            'info': 1
        }
        
        total_score = sum(risk_weights.get(finding.severity, 0) for finding in self.security_findings)
        self.risk_score = min(100, total_score)
    
    def get_high_severity_findings(self) -> List[SecurityFinding]:
        """Get critical and high severity findings"""
        return [f for f in self.security_findings 
                if f.severity in ['critical', 'high']]
    
    def update_enhanced_risk_score(self, risk_score: RiskScore) -> None:
        """Update the enhanced risk score"""
        self.enhanced_risk_score = risk_score
        # Also update the legacy risk score for backwards compatibility
        self.risk_score = int(risk_score.overall_score)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert asset to dictionary for storage"""
        return {
            'asset_id': self.asset_id,
            'asset_type': self.asset_type.value,
            'service_name': self.service_name,
            'region': self.region,
            'name': self.name,
            'arn': self.arn,
            'tags': self.tags,
            'metadata': {
                'discovery_method': self.metadata.discovery_method if self.metadata else None,
                'scope': self.metadata.scope if self.metadata else None,
                'last_updated': self.metadata.last_updated.isoformat() if self.metadata else None
            } if self.metadata else None,
            'security_findings': [
                {
                    'finding_id': f.finding_id,
                    'title': f.title,
                    'description': f.description,
                    'severity': f.severity,
                    'finding_type': f.finding_type,
                    'compliance_frameworks': f.compliance_frameworks,
                    'remediation': f.remediation,
                    'created_at': f.created_at.isoformat() if f.created_at else None,
                    'resource_id': f.resource_id
                } for f in self.security_findings
            ],
            'risk_score': self.risk_score,
            'enhanced_risk_score': {
                'overall_score': self.enhanced_risk_score.overall_score,
                'risk_level': self.enhanced_risk_score.risk_level,
                'category_scores': self.enhanced_risk_score.category_scores,
                'findings_count': self.enhanced_risk_score.findings_count,
                'critical_findings': self.enhanced_risk_score.critical_findings,
                'high_findings': self.enhanced_risk_score.high_findings,
                'medium_findings': self.enhanced_risk_score.medium_findings,
                'low_findings': self.enhanced_risk_score.low_findings,
                'calculated_at': self.enhanced_risk_score.calculated_at,
                'threat_vectors': self.enhanced_risk_score.threat_vectors,
                'risk_factors': self.enhanced_risk_score.risk_factors
            } if self.enhanced_risk_score else None,
            'compliance_status': self.compliance_status,
            'relationships': self.relationships,
            'state': self.state,
            'created_at': self.created_at.isoformat(),
            'last_scan_at': self.last_scan_at.isoformat() if self.last_scan_at else None
        }

@dataclass 
class AssetRelationship:
    """Represents a relationship between assets"""
    source_asset_id: str
    target_asset_id: str
    relationship_type: str
    relationship_data: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.utcnow)
    
    def __post_init__(self):
        if not self.relationship_data:
            self.relationship_data = {}

@dataclass
class ComplianceResult:
    """Compliance check result"""
    framework: str
    control_id: str
    control_title: str
    status: str  # compliant, non_compliant, not_applicable
    severity: str
    description: str
    remediation: Optional[str] = None
    evidence: Dict[str, Any] = field(default_factory=dict)
    checked_at: datetime = field(default_factory=datetime.utcnow)
    
    def __post_init__(self):
        if not self.evidence:
            self.evidence = {}

@dataclass
class InventoryScanSession:
    """Represents an inventory scan session"""
    scan_id: str
    tenant_id: str
    scan_type: str
    regions: List[str]
    services: List[str]
    status: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    total_assets: int = 0
    total_findings: int = 0
    error_count: int = 0
    summary: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        if not self.summary:
            self.summary = {}

@dataclass
class AssetFilter:
    """Filter criteria for asset queries"""
    services: Optional[List[str]] = None
    regions: Optional[List[str]] = None
    resource_types: Optional[List[str]] = None
    risk_levels: Optional[List[str]] = None
    compliance_frameworks: Optional[List[str]] = None
    tags: Optional[Dict[str, str]] = None
    min_risk_score: Optional[float] = None
    max_risk_score: Optional[float] = None
    has_findings: Optional[bool] = None
    finding_severities: Optional[List[str]] = None
    
    def __post_init__(self):
        # Ensure all list fields are properly initialized
        if self.services is None:
            self.services = []
        if self.regions is None:
            self.regions = []
        if self.resource_types is None:
            self.resource_types = []
        if self.risk_levels is None:
            self.risk_levels = []
        if self.compliance_frameworks is None:
            self.compliance_frameworks = []
        if self.tags is None:
            self.tags = {}
        if self.finding_severities is None:
            self.finding_severities = []

# Utility functions for model operations
def convert_asset_info_to_asset(asset_info: AssetInfo, tenant_id: str) -> Asset:
    """Convert AssetInfo from discovery to Asset model"""
    # Determine asset type from service
    asset_type_mapping = {
        'ec2': AssetType.COMPUTE,
        'lambda': AssetType.COMPUTE,
        'ecs': AssetType.COMPUTE,
        'eks': AssetType.COMPUTE,
        's3': AssetType.STORAGE,
        'rds': AssetType.DATABASE,
        'dynamodb': AssetType.DATABASE,
        'vpc': AssetType.NETWORK,
        'elbv2': AssetType.NETWORK,
        'iam': AssetType.IDENTITY,
        'kms': AssetType.SECURITY,
        'cloudtrail': AssetType.MONITORING,
        'cloudwatch': AssetType.MONITORING,
        'athena': AssetType.ANALYTICS,
        'glue': AssetType.ANALYTICS
    }
    
    asset_type = asset_type_mapping.get(asset_info.service, AssetType.OTHER)
    
    # Convert tags format
    tags_dict = {}
    for tag in asset_info.tags:
        if isinstance(tag, dict) and 'Key' in tag and 'Value' in tag:
            tags_dict[tag['Key']] = tag['Value']
    
    # Create asset
    asset = Asset(
        asset_id=f"{tenant_id}:{asset_info.service}:{asset_info.region}:{asset_info.resource_id}",
        asset_type=asset_type,
        service_name=asset_info.service,
        region=asset_info.region,
        name=asset_info.name or asset_info.resource_id,
        arn=asset_info.arn,
        tags=tags_dict,
        metadata=AssetMetadata(
            discovery_method="automated",
            scope="regional" if asset_info.region != "global" else "global",
            raw_data=asset_info.configuration
        ),
        security_findings=asset_info.security_findings,
        enhanced_risk_score=asset_info.risk_score
    )
    
    return asset
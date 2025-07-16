#!/usr/bin/env python3
"""
Security Finding Data Models for LG-Protect Inventory System

Provides comprehensive data structures for security findings, vulnerabilities,
and compliance issues discovered during asset analysis.
"""

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, field, asdict
import structlog

logger = structlog.get_logger(__name__)

class RiskLevel(Enum):
    """Risk severity levels aligned with industry standards"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"

class FindingCategory(Enum):
    """Security finding categories for classification"""
    NETWORK_EXPOSURE = "network_exposure"
    DATA_PROTECTION = "data_protection"
    IDENTITY_SECURITY = "identity_security"
    ACCESS_CONTROL = "access_control"
    ENCRYPTION = "encryption"
    MONITORING = "monitoring"
    COMPLIANCE = "compliance"
    CONFIGURATION = "configuration"
    VULNERABILITY = "vulnerability"
    MALWARE = "malware"
    ANOMALY = "anomaly"
    POLICY_VIOLATION = "policy_violation"

class FindingStatus(Enum):
    """Finding lifecycle status"""
    ACTIVE = "active"
    RESOLVED = "resolved"
    SUPPRESSED = "suppressed"
    FALSE_POSITIVE = "false_positive"
    UNDER_REVIEW = "under_review"
    PLANNED = "planned"

class ComplianceFramework(Enum):
    """Supported compliance frameworks"""
    CIS = "cis"
    SOC2 = "soc2"
    NIST = "nist"
    PCI_DSS = "pci_dss"
    HIPAA = "hipaa"
    ISO27001 = "iso27001"
    MITRE_ATTACK = "mitre_attack"
    AWS_FOUNDATIONAL = "aws_foundational"
    GDPR = "gdpr"

@dataclass
class FindingEvidence:
    """Evidence supporting a security finding"""
    evidence_type: str  # api_response, configuration, log_entry, etc.
    evidence_data: Dict[str, Any] = field(default_factory=dict)
    evidence_description: str = ""
    collected_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    
    def __post_init__(self):
        """Validate evidence data"""
        if not self.evidence_type:
            raise ValueError("Evidence type is required")

@dataclass
class ComplianceMapping:
    """Mapping to compliance frameworks and controls"""
    framework: ComplianceFramework
    control_id: str
    control_name: str = ""
    requirement: str = ""
    compliance_status: str = "non_compliant"  # compliant, non_compliant, not_applicable
    
    def __post_init__(self):
        """Validate compliance mapping"""
        if not self.control_id:
            raise ValueError("Control ID is required for compliance mapping")

@dataclass
class Remediation:
    """Remediation guidance for security findings"""
    remediation_type: str  # manual, automated, policy, configuration
    description: str = ""
    steps: List[str] = field(default_factory=list)
    automation_script: Optional[str] = None
    estimated_effort: str = ""  # minutes, hours, days
    priority: str = "medium"  # high, medium, low
    
    def __post_init__(self):
        """Validate remediation data"""
        if not self.remediation_type:
            raise ValueError("Remediation type is required")

@dataclass
class SecurityFinding:
    """
    Enterprise-grade security finding model
    
    Supports:
    - Multi-framework compliance mapping
    - Evidence collection and validation
    - Remediation guidance
    - Risk scoring and prioritization
    - Finding lifecycle management
    """
    
    # Core Identity
    finding_id: str = field(default_factory=lambda: f"finding-{str(uuid.uuid4())}")
    title: str = ""
    description: str = ""
    
    # Classification
    severity: RiskLevel = RiskLevel.UNKNOWN
    category: FindingCategory = FindingCategory.CONFIGURATION
    finding_type: str = ""  # specific finding type within category
    
    # Asset Association
    asset_id: str = ""
    asset_urn: str = ""
    service_name: str = ""
    resource_type: str = ""
    
    # Location Context
    account_id: str = ""
    region: str = ""
    
    # Finding Details
    risk_score: float = 0.0  # 0.0 to 100.0
    confidence_score: float = 1.0  # 0.0 to 1.0
    business_impact: str = ""
    technical_impact: str = ""
    
    # Status & Lifecycle
    status: FindingStatus = FindingStatus.ACTIVE
    first_detected: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    last_detected: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    resolved_at: Optional[str] = None
    
    # Evidence & Proof
    evidence: List[FindingEvidence] = field(default_factory=list)
    
    # Compliance & Frameworks
    compliance_mappings: List[ComplianceMapping] = field(default_factory=list)
    
    # Remediation
    remediation: Optional[Remediation] = None
    
    # Attribution
    detection_source: str = "lg_protect"  # lg_protect, aws_security_hub, guard_duty, etc.
    detection_method: str = ""
    source_finding_id: Optional[str] = None  # ID from external system
    
    # Metadata
    tags: Dict[str, str] = field(default_factory=dict)
    custom_fields: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Post-initialization validation and setup"""
        try:
            # Validate required fields
            self._validate_required_fields()
            
            # Calculate risk score if not provided
            if self.risk_score == 0.0:
                self.risk_score = self._calculate_default_risk_score()
            
            logger.debug("security_finding_created", 
                        finding_id=self.finding_id,
                        severity=self.severity.value,
                        category=self.category.value,
                        asset_id=self.asset_id)
                        
        except Exception as e:
            logger.error("security_finding_creation_failed", 
                        finding_id=getattr(self, 'finding_id', 'unknown'),
                        error=str(e))
            raise
    
    def _validate_required_fields(self):
        """Validate required fields for enterprise compliance"""
        required_fields = {
            'finding_id': self.finding_id,
            'title': self.title,
            'asset_id': self.asset_id,
            'account_id': self.account_id
        }
        
        missing_fields = [field for field, value in required_fields.items() if not value]
        
        if missing_fields:
            raise ValueError(f"Missing required finding fields: {missing_fields}")
    
    def _calculate_default_risk_score(self) -> float:
        """Calculate default risk score based on severity"""
        severity_scores = {
            RiskLevel.CRITICAL: 90.0,
            RiskLevel.HIGH: 70.0,
            RiskLevel.MEDIUM: 50.0,
            RiskLevel.LOW: 30.0,
            RiskLevel.INFO: 10.0,
            RiskLevel.UNKNOWN: 0.0
        }
        return severity_scores.get(self.severity, 0.0)
    
    def add_evidence(self, evidence_type: str, evidence_data: Dict[str, Any], 
                    description: str = "") -> None:
        """Add evidence to support the finding"""
        try:
            evidence = FindingEvidence(
                evidence_type=evidence_type,
                evidence_data=evidence_data,
                evidence_description=description
            )
            
            self.evidence.append(evidence)
            self.last_detected = datetime.now(timezone.utc).isoformat()
            
            logger.debug("finding_evidence_added", 
                       finding_id=self.finding_id,
                       evidence_type=evidence_type)
                       
        except Exception as e:
            logger.error("finding_evidence_addition_failed", 
                        finding_id=self.finding_id,
                        evidence_type=evidence_type,
                        error=str(e))
            raise
    
    def add_compliance_mapping(self, framework: ComplianceFramework, 
                             control_id: str, control_name: str = "",
                             requirement: str = "") -> None:
        """Add compliance framework mapping"""
        try:
            mapping = ComplianceMapping(
                framework=framework,
                control_id=control_id,
                control_name=control_name,
                requirement=requirement
            )
            
            # Check if mapping already exists
            existing_mapping = self.get_compliance_mapping(framework, control_id)
            if existing_mapping:
                # Update existing mapping
                existing_mapping.control_name = control_name or existing_mapping.control_name
                existing_mapping.requirement = requirement or existing_mapping.requirement
            else:
                self.compliance_mappings.append(mapping)
            
            logger.debug("finding_compliance_mapping_added", 
                       finding_id=self.finding_id,
                       framework=framework.value,
                       control_id=control_id)
                       
        except Exception as e:
            logger.error("finding_compliance_mapping_failed", 
                        finding_id=self.finding_id,
                        framework=framework.value if isinstance(framework, ComplianceFramework) else str(framework),
                        error=str(e))
            raise
    
    def get_compliance_mapping(self, framework: ComplianceFramework, 
                             control_id: str) -> Optional[ComplianceMapping]:
        """Get compliance mapping for specific framework and control"""
        try:
            for mapping in self.compliance_mappings:
                if mapping.framework == framework and mapping.control_id == control_id:
                    return mapping
            return None
        except Exception as e:
            logger.error("finding_compliance_mapping_retrieval_failed", 
                        finding_id=self.finding_id,
                        error=str(e))
            return None
    
    def set_remediation(self, remediation_type: str, description: str = "",
                       steps: List[str] = None, automation_script: str = None,
                       estimated_effort: str = "", priority: str = "medium") -> None:
        """Set remediation guidance for the finding"""
        try:
            self.remediation = Remediation(
                remediation_type=remediation_type,
                description=description,
                steps=steps or [],
                automation_script=automation_script,
                estimated_effort=estimated_effort,
                priority=priority
            )
            
            logger.debug("finding_remediation_set", 
                       finding_id=self.finding_id,
                       remediation_type=remediation_type,
                       priority=priority)
                       
        except Exception as e:
            logger.error("finding_remediation_setting_failed", 
                        finding_id=self.finding_id,
                        error=str(e))
            raise
    
    def update_status(self, new_status: FindingStatus, 
                     resolution_note: str = "") -> None:
        """Update finding status with validation"""
        try:
            old_status = self.status
            self.status = new_status
            
            # Set resolved timestamp if moving to resolved state
            if new_status == FindingStatus.RESOLVED and not self.resolved_at:
                self.resolved_at = datetime.now(timezone.utc).isoformat()
            
            # Clear resolved timestamp if moving away from resolved state
            if new_status != FindingStatus.RESOLVED and self.resolved_at:
                self.resolved_at = None
            
            # Add resolution note as custom field
            if resolution_note:
                self.custom_fields['resolution_note'] = resolution_note
                self.custom_fields['status_updated_at'] = datetime.now(timezone.utc).isoformat()
            
            logger.info("finding_status_updated", 
                       finding_id=self.finding_id,
                       old_status=old_status.value,
                       new_status=new_status.value)
                       
        except Exception as e:
            logger.error("finding_status_update_failed", 
                        finding_id=self.finding_id,
                        error=str(e))
            raise
    
    def update_risk_score(self, risk_score: float, justification: str = "") -> None:
        """Update risk score with validation and justification"""
        try:
            if not 0.0 <= risk_score <= 100.0:
                raise ValueError(f"Risk score must be between 0.0 and 100.0, got: {risk_score}")
            
            old_score = self.risk_score
            self.risk_score = risk_score
            
            if justification:
                self.custom_fields['risk_score_justification'] = justification
                self.custom_fields['risk_score_updated_at'] = datetime.now(timezone.utc).isoformat()
            
            logger.info("finding_risk_score_updated", 
                       finding_id=self.finding_id,
                       old_score=old_score,
                       new_score=risk_score)
                       
        except Exception as e:
            logger.error("finding_risk_score_update_failed", 
                        finding_id=self.finding_id,
                        error=str(e))
            raise
    
    def get_age_days(self) -> int:
        """Get finding age in days"""
        try:
            first_detected_dt = datetime.fromisoformat(self.first_detected.replace('Z', '+00:00'))
            current_dt = datetime.now(timezone.utc)
            return (current_dt - first_detected_dt).days
        except Exception as e:
            logger.error("finding_age_calculation_failed", 
                        finding_id=self.finding_id,
                        error=str(e))
            return 0
    
    def is_stale(self, stale_days: int = 30) -> bool:
        """Check if finding is stale (not updated recently)"""
        try:
            last_detected_dt = datetime.fromisoformat(self.last_detected.replace('Z', '+00:00'))
            current_dt = datetime.now(timezone.utc)
            return (current_dt - last_detected_dt).days > stale_days
        except Exception as e:
            logger.error("finding_staleness_check_failed", 
                        finding_id=self.finding_id,
                        error=str(e))
            return False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary for serialization"""
        try:
            finding_dict = asdict(self)
            
            # Convert enums to strings
            finding_dict['severity'] = self.severity.value
            finding_dict['category'] = self.category.value
            finding_dict['status'] = self.status.value
            
            # Convert compliance mappings
            finding_dict['compliance_mappings'] = [
                {
                    'framework': mapping.framework.value,
                    'control_id': mapping.control_id,
                    'control_name': mapping.control_name,
                    'requirement': mapping.requirement,
                    'compliance_status': mapping.compliance_status
                }
                for mapping in self.compliance_mappings
            ]
            
            return finding_dict
            
        except Exception as e:
            logger.error("finding_serialization_failed", 
                        finding_id=self.finding_id,
                        error=str(e))
            raise
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SecurityFinding':
        """Create finding from dictionary with validation"""
        try:
            # Convert string enums back to enum objects
            if 'severity' in data and isinstance(data['severity'], str):
                data['severity'] = RiskLevel(data['severity'])
            if 'category' in data and isinstance(data['category'], str):
                data['category'] = FindingCategory(data['category'])
            if 'status' in data and isinstance(data['status'], str):
                data['status'] = FindingStatus(data['status'])
            
            # Handle nested objects
            if 'evidence' in data and isinstance(data['evidence'], list):
                data['evidence'] = [
                    FindingEvidence(**evidence) if isinstance(evidence, dict) else evidence 
                    for evidence in data['evidence']
                ]
            
            if 'compliance_mappings' in data and isinstance(data['compliance_mappings'], list):
                data['compliance_mappings'] = [
                    ComplianceMapping(
                        framework=ComplianceFramework(mapping['framework']),
                        control_id=mapping['control_id'],
                        control_name=mapping.get('control_name', ''),
                        requirement=mapping.get('requirement', ''),
                        compliance_status=mapping.get('compliance_status', 'non_compliant')
                    ) if isinstance(mapping, dict) else mapping
                    for mapping in data['compliance_mappings']
                ]
            
            if 'remediation' in data and isinstance(data['remediation'], dict):
                data['remediation'] = Remediation(**data['remediation'])
            
            return cls(**data)
            
        except Exception as e:
            logger.error("finding_deserialization_failed", 
                        data_keys=list(data.keys()) if isinstance(data, dict) else "invalid_data",
                        error=str(e))
            raise
    
    def __str__(self) -> str:
        """String representation for debugging"""
        return f"SecurityFinding(id={self.finding_id}, severity={self.severity.value}, category={self.category.value}, asset={self.asset_id})"
    
    def __repr__(self) -> str:
        """Detailed representation for debugging"""
        return f"SecurityFinding(finding_id='{self.finding_id}', severity={self.severity}, category={self.category}, title='{self.title}', status={self.status})"
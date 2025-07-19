#!/usr/bin/env python3
"""
Risk Calculator for LG-Protect Inventory System

Advanced risk calculation engine that provides quantitative risk scoring
for AWS assets based on security findings, compliance violations, and threat intelligence.
"""

import asyncio
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timedelta
import structlog
from dataclasses import dataclass
from enum import Enum
import math

from ..models.asset_models import AssetInfo, SecurityFinding, RiskScore
from ..utils.service_enablement_integration import get_service_enablement_integration

logger = structlog.get_logger(__name__)

class RiskLevel(Enum):
    """Risk level classifications"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    MINIMAL = "minimal"

@dataclass
class ThreatVector:
    """Represents a potential threat vector"""
    name: str
    probability: float  # 0.0 to 1.0
    impact: float      # 0.0 to 1.0
    exploitability: float  # 0.0 to 1.0
    description: str

@dataclass
class AssetContext:
    """Additional context for risk calculation"""
    business_criticality: str  # critical, high, medium, low
    data_classification: str   # public, internal, confidential, restricted
    network_exposure: str      # internet, vpc, private
    compliance_requirements: List[str]
    age_days: int
    change_frequency: str      # high, medium, low

class RiskCalculator:
    """
    Advanced risk calculator for CSPM assets
    """
    
    def __init__(self):
        # Risk scoring weights by category
        self.category_weights = {
            'encryption': 0.20,
            'access_control': 0.18,
            'network_security': 0.16,
            'logging_monitoring': 0.12,
            'configuration': 0.12,
            'backup_recovery': 0.10,
            'compliance': 0.08,
            'data_protection': 0.04
        }
        
        # Severity impact multipliers
        self.severity_impact = {
            'critical': 1.0,
            'high': 0.8,
            'medium': 0.6,
            'low': 0.4,
            'info': 0.2
        }
        
        # Service criticality multipliers
        self.service_criticality = {
            's3': 1.0,           # High - data storage
            'rds': 1.0,          # High - database
            'ec2': 0.9,          # High - compute
            'iam': 1.0,          # High - identity
            'lambda': 0.8,       # Medium-High - serverless
            'kms': 1.0,          # High - encryption
            'vpc': 0.9,          # High - network
            'cloudtrail': 0.9,   # High - logging
            'elbv2': 0.8,        # Medium-High - load balancer
            'dynamodb': 0.9,     # High - database
            'eks': 0.9,          # High - container orchestration
            'ecs': 0.8,          # Medium-High - containers
            'secretsmanager': 1.0, # High - secrets
            'guardduty': 0.7,    # Medium - security service
            'config': 0.7,       # Medium - compliance
            'cloudwatch': 0.6,   # Medium - monitoring
            'sns': 0.5,          # Medium - messaging
            'sqs': 0.5,          # Medium - messaging
        }
        
        # Default service criticality for unknown services
        self.default_criticality = 0.6
        
        # Threat vectors by service
        self.threat_vectors = self._initialize_threat_vectors()
        
    def _initialize_threat_vectors(self) -> Dict[str, List[ThreatVector]]:
        """Initialize threat vectors for different services"""
        return {
            's3': [
                ThreatVector("data_exposure", 0.8, 0.9, 0.7, "Public bucket exposure"),
                ThreatVector("data_exfiltration", 0.6, 0.9, 0.5, "Unauthorized data download"),
                ThreatVector("ransomware", 0.4, 0.8, 0.6, "Encryption/deletion attacks"),
                ThreatVector("compliance_violation", 0.7, 0.6, 0.8, "Regulatory violations")
            ],
            'ec2': [
                ThreatVector("lateral_movement", 0.7, 0.8, 0.7, "Network-based attacks"),
                ThreatVector("privilege_escalation", 0.6, 0.8, 0.6, "Local privilege escalation"),
                ThreatVector("malware_deployment", 0.5, 0.9, 0.7, "Malicious software installation"),
                ThreatVector("resource_hijacking", 0.4, 0.7, 0.8, "Cryptomining/resource abuse")
            ],
            'rds': [
                ThreatVector("data_breach", 0.8, 1.0, 0.6, "Database breach"),
                ThreatVector("injection_attacks", 0.7, 0.8, 0.8, "SQL injection"),
                ThreatVector("unauthorized_access", 0.6, 0.9, 0.7, "Credential compromise"),
                ThreatVector("data_corruption", 0.3, 0.9, 0.5, "Data integrity attacks")
            ],
            'iam': [
                ThreatVector("privilege_escalation", 0.8, 1.0, 0.7, "Permission escalation"),
                ThreatVector("credential_stuffing", 0.7, 0.8, 0.8, "Credential attacks"),
                ThreatVector("account_takeover", 0.6, 1.0, 0.6, "Account compromise"),
                ThreatVector("backdoor_creation", 0.4, 0.9, 0.5, "Persistent access")
            ]
        }
    
    async def calculate_asset_risk(self, asset: AssetInfo, 
                                 findings: List[SecurityFinding],
                                 context: Optional[AssetContext] = None) -> RiskScore:
        """
        Calculate comprehensive risk score for an asset
        """
        try:
            logger.debug("calculating_asset_risk", 
                        asset_id=asset.resource_id,
                        findings_count=len(findings))
            
            # 1. Base risk calculation from findings
            base_risk = self._calculate_base_risk(findings)
            
            # 2. Service-specific risk adjustment
            service_risk = self._calculate_service_risk(asset, findings)
            
            # 3. Context-based risk adjustment
            context_risk = self._calculate_context_risk(asset, context) if context else 1.0
            
            # 4. Threat vector analysis
            threat_risk = self._calculate_threat_risk(asset, findings)
            
            # 5. Temporal risk factors
            temporal_risk = self._calculate_temporal_risk(asset, findings)
            
            # Combine risk factors
            overall_score = self._combine_risk_factors(
                base_risk, service_risk, context_risk, threat_risk, temporal_risk
            )
            
            # Calculate category-specific scores
            category_scores = self._calculate_category_scores(findings)
            
            # Determine risk level
            risk_level = self._determine_risk_level(overall_score)
            
            # Calculate additional metrics
            risk_score = RiskScore(
                overall_score=round(overall_score, 2),
                risk_level=risk_level.value,
                category_scores=category_scores,
                findings_count=len(findings),
                critical_findings=len([f for f in findings if f.severity == 'critical']),
                high_findings=len([f for f in findings if f.severity == 'high']),
                medium_findings=len([f for f in findings if f.severity == 'medium']),
                low_findings=len([f for f in findings if f.severity == 'low']),
                calculated_at=datetime.now().isoformat(),
                threat_vectors=self._get_applicable_threats(asset),
                risk_factors={
                    'base_risk': round(base_risk, 2),
                    'service_risk': round(service_risk, 2),
                    'context_risk': round(context_risk, 2),
                    'threat_risk': round(threat_risk, 2),
                    'temporal_risk': round(temporal_risk, 2)
                }
            )
            
            logger.info("asset_risk_calculated",
                       asset_id=asset.resource_id,
                       overall_score=overall_score,
                       risk_level=risk_level.value)
            
            return risk_score
            
        except Exception as e:
            logger.error("asset_risk_calculation_failed",
                        asset_id=asset.resource_id,
                        error=str(e))
            return RiskScore(overall_score=0.0, category_scores={})
    
    def _calculate_base_risk(self, findings: List[SecurityFinding]) -> float:
        """Calculate base risk score from security findings"""
        if not findings:
            return 0.0
        
        # Group findings by category
        category_findings = {}
        for finding in findings:
            category = finding.finding_type
            if category not in category_findings:
                category_findings[category] = []
            category_findings[category].append(finding)
        
        # Calculate weighted category scores
        total_weighted_score = 0.0
        total_weight = 0.0
        
        for category, category_list in category_findings.items():
            # Calculate category severity score
            category_score = 0.0
            for finding in category_list:
                severity_score = self.severity_impact.get(finding.severity, 0.5)
                category_score += severity_score * 20  # Scale to 0-100
            
            # Apply category weight
            weight = self.category_weights.get(category, 0.05)
            total_weighted_score += category_score * weight
            total_weight += weight
        
        # Normalize score
        if total_weight > 0:
            base_score = min(100.0, total_weighted_score / total_weight)
        else:
            base_score = 0.0
        
        return base_score
    
    def _calculate_service_risk(self, asset: AssetInfo, findings: List[SecurityFinding]) -> float:
        """Calculate service-specific risk multiplier"""
        service_criticality = self.service_criticality.get(
            asset.service, self.default_criticality
        )
        
        # Adjust based on resource type
        if asset.resource_type in ['database', 'bucket', 'user', 'role', 'policy']:
            service_criticality *= 1.1  # Higher criticality for sensitive resource types
        
        return service_criticality
    
    def _calculate_context_risk(self, asset: AssetInfo, context: AssetContext) -> float:
        """Calculate context-based risk multiplier"""
        multiplier = 1.0
        
        # Business criticality adjustment
        criticality_multipliers = {
            'critical': 1.3,
            'high': 1.2,
            'medium': 1.0,
            'low': 0.8
        }
        multiplier *= criticality_multipliers.get(context.business_criticality, 1.0)
        
        # Data classification adjustment
        classification_multipliers = {
            'restricted': 1.4,
            'confidential': 1.2,
            'internal': 1.0,
            'public': 0.8
        }
        multiplier *= classification_multipliers.get(context.data_classification, 1.0)
        
        # Network exposure adjustment
        exposure_multipliers = {
            'internet': 1.5,
            'vpc': 1.0,
            'private': 0.7
        }
        multiplier *= exposure_multipliers.get(context.network_exposure, 1.0)
        
        # Age factor (older resources may have accumulated more risk)
        if context.age_days > 365:
            multiplier *= 1.1
        elif context.age_days > 730:
            multiplier *= 1.2
        
        return multiplier
    
    def _calculate_threat_risk(self, asset: AssetInfo, findings: List[SecurityFinding]) -> float:
        """Calculate threat-specific risk score"""
        threats = self.threat_vectors.get(asset.service, [])
        if not threats:
            return 1.0  # Neutral multiplier if no specific threats defined
        
        # Calculate threat exposure based on findings
        threat_exposure = 0.0
        for threat in threats:
            # Check if findings indicate exposure to this threat
            exposure_level = self._assess_threat_exposure(threat, findings)
            threat_score = threat.probability * threat.impact * threat.exploitability * exposure_level
            threat_exposure += threat_score
        
        # Normalize and convert to multiplier
        if threats:
            avg_threat_score = threat_exposure / len(threats)
            return 1.0 + (avg_threat_score * 0.5)  # Max 1.5x multiplier
        
        return 1.0
    
    def _assess_threat_exposure(self, threat: ThreatVector, findings: List[SecurityFinding]) -> float:
        """Assess how exposed an asset is to a specific threat based on findings"""
        exposure = 0.0
        
        # Map threat types to finding types
        threat_finding_map = {
            'data_exposure': ['access_control', 'network_security'],
            'data_exfiltration': ['access_control', 'encryption', 'logging_monitoring'],
            'lateral_movement': ['network_security', 'access_control'],
            'privilege_escalation': ['access_control', 'configuration'],
            'data_breach': ['encryption', 'access_control', 'network_security'],
            'injection_attacks': ['configuration', 'access_control'],
            'credential_stuffing': ['access_control', 'logging_monitoring']
        }
        
        relevant_categories = threat_finding_map.get(threat.name, [])
        
        for finding in findings:
            if finding.finding_type in relevant_categories:
                severity_impact = self.severity_impact.get(finding.severity, 0.5)
                exposure += severity_impact
        
        # Normalize to 0-1 range
        return min(1.0, exposure / 3.0)  # Assuming max 3 relevant findings per threat
    
    def _calculate_temporal_risk(self, asset: AssetInfo, findings: List[SecurityFinding]) -> float:
        """Calculate temporal risk factors"""
        multiplier = 1.0
        
        # Recent findings increase risk
        now = datetime.now()
        recent_critical = 0
        
        for finding in findings:
            if finding.severity == 'critical':
                # Assume finding is recent if no timestamp available
                recent_critical += 1
        
        if recent_critical > 0:
            multiplier *= 1.0 + (recent_critical * 0.1)  # 10% increase per critical finding
        
        # Asset age factor
        if asset.created_date:
            try:
                if isinstance(asset.created_date, str):
                    created_date = datetime.fromisoformat(asset.created_date.replace('Z', '+00:00'))
                else:
                    created_date = asset.created_date
                
                age_days = (now - created_date.replace(tzinfo=None)).days
                
                # Newer assets might have configuration issues
                if age_days < 30:
                    multiplier *= 1.1
                # Very old assets might have accumulated risk
                elif age_days > 730:
                    multiplier *= 1.05
                    
            except Exception as e:
                logger.debug("temporal_risk_calculation_error", error=str(e))
        
        return multiplier
    
    def _combine_risk_factors(self, base_risk: float, service_risk: float, 
                            context_risk: float, threat_risk: float, 
                            temporal_risk: float) -> float:
        """Combine all risk factors into final score"""
        # Base risk is the foundation (0-100)
        combined_score = base_risk
        
        # Apply multipliers
        combined_score *= service_risk
        combined_score *= context_risk
        combined_score *= threat_risk
        combined_score *= temporal_risk
        
        # Ensure score stays within bounds
        return min(100.0, max(0.0, combined_score))
    
    def _calculate_category_scores(self, findings: List[SecurityFinding]) -> Dict[str, float]:
        """Calculate risk scores by category"""
        category_scores = {}
        
        # Initialize all categories
        for category in self.category_weights.keys():
            category_scores[category] = 100.0  # Start with perfect score
        
        # Reduce scores based on findings
        for finding in findings:
            category = finding.finding_type
            if category in category_scores:
                severity_impact = self.severity_impact.get(finding.severity, 0.5)
                reduction = severity_impact * 25  # Max 25 points reduction per finding
                category_scores[category] = max(0.0, category_scores[category] - reduction)
        
        return category_scores
    
    def _determine_risk_level(self, score: float) -> RiskLevel:
        """Determine risk level based on score"""
        if score >= 80:
            return RiskLevel.CRITICAL
        elif score >= 60:
            return RiskLevel.HIGH
        elif score >= 40:
            return RiskLevel.MEDIUM
        elif score >= 20:
            return RiskLevel.LOW
        else:
            return RiskLevel.MINIMAL
    
    def _get_applicable_threats(self, asset: AssetInfo) -> List[str]:
        """Get list of applicable threat vectors for an asset"""
        threats = self.threat_vectors.get(asset.service, [])
        return [threat.name for threat in threats]
    
    async def calculate_portfolio_risk(self, asset_risks: Dict[str, RiskScore]) -> Dict[str, Any]:
        """Calculate portfolio-level risk metrics"""
        try:
            if not asset_risks:
                return {}
            
            scores = [risk.overall_score for risk in asset_risks.values()]
            total_findings = sum(risk.findings_count for risk in asset_risks.values())
            
            # Calculate aggregated metrics
            portfolio_metrics = {
                'total_assets': len(asset_risks),
                'average_risk_score': sum(scores) / len(scores) if scores else 0.0,
                'max_risk_score': max(scores) if scores else 0.0,
                'min_risk_score': min(scores) if scores else 0.0,
                'total_findings': total_findings,
                'risk_distribution': {
                    'critical': len([r for r in asset_risks.values() if r.risk_level == 'critical']),
                    'high': len([r for r in asset_risks.values() if r.risk_level == 'high']),
                    'medium': len([r for r in asset_risks.values() if r.risk_level == 'medium']),
                    'low': len([r for r in asset_risks.values() if r.risk_level == 'low']),
                    'minimal': len([r for r in asset_risks.values() if r.risk_level == 'minimal'])
                },
                'calculated_at': datetime.now().isoformat()
            }
            
            # Calculate risk trends (placeholder for time-series analysis)
            portfolio_metrics['risk_trends'] = {
                'trend_direction': 'stable',  # would be calculated from historical data
                'risk_velocity': 0.0  # rate of risk change
            }
            
            return portfolio_metrics
            
        except Exception as e:
            logger.error("portfolio_risk_calculation_failed", error=str(e))
            return {}
    
    def get_risk_recommendations(self, asset: AssetInfo, risk_score: RiskScore, 
                               findings: List[SecurityFinding]) -> List[Dict[str, Any]]:
        """Generate risk-based recommendations"""
        recommendations = []
        
        try:
            # Priority-based recommendations
            critical_findings = [f for f in findings if f.severity == 'critical']
            high_findings = [f for f in findings if f.severity == 'high']
            
            # Immediate actions for critical findings
            for finding in critical_findings:
                recommendations.append({
                    'priority': 'immediate',
                    'category': finding.finding_type,
                    'title': f"Address {finding.title}",
                    'description': finding.description,
                    'remediation': finding.remediation,
                    'estimated_risk_reduction': 20,
                    'effort_level': 'high'
                })
            
            # Short-term actions for high findings
            for finding in high_findings:
                recommendations.append({
                    'priority': 'short_term',
                    'category': finding.finding_type,
                    'title': f"Resolve {finding.title}",
                    'description': finding.description,
                    'remediation': finding.remediation,
                    'estimated_risk_reduction': 10,
                    'effort_level': 'medium'
                })
            
            # Service-specific recommendations
            service_recommendations = self._get_service_specific_recommendations(asset, risk_score)
            recommendations.extend(service_recommendations)
            
            # Sort by priority and potential impact
            recommendations.sort(key=lambda x: (
                {'immediate': 0, 'short_term': 1, 'long_term': 2}.get(x['priority'], 3),
                -x.get('estimated_risk_reduction', 0)
            ))
            
            return recommendations[:10]  # Return top 10 recommendations
            
        except Exception as e:
            logger.error("risk_recommendations_failed", 
                        asset_id=asset.resource_id, error=str(e))
            return []
    
    def _get_service_specific_recommendations(self, asset: AssetInfo, 
                                           risk_score: RiskScore) -> List[Dict[str, Any]]:
        """Get service-specific recommendations"""
        recommendations = []
        
        service_recommendations = {
            's3': [
                {
                    'priority': 'short_term',
                    'category': 'encryption',
                    'title': 'Enable S3 bucket encryption',
                    'description': 'Implement server-side encryption for data protection',
                    'estimated_risk_reduction': 15,
                    'effort_level': 'low'
                }
            ],
            'ec2': [
                {
                    'priority': 'immediate',
                    'category': 'network_security',
                    'title': 'Review security group rules',
                    'description': 'Ensure least privilege access in security groups',
                    'estimated_risk_reduction': 18,
                    'effort_level': 'medium'
                }
            ],
            'rds': [
                {
                    'priority': 'immediate',
                    'category': 'encryption',
                    'title': 'Enable RDS encryption',
                    'description': 'Enable encryption at rest for database security',
                    'estimated_risk_reduction': 20,
                    'effort_level': 'medium'
                }
            ]
        }
        
        service_recs = service_recommendations.get(asset.service, [])
        return service_recs

# Global risk calculator instance
_risk_calculator = None

def get_risk_calculator() -> RiskCalculator:
    """Get the global risk calculator instance"""
    global _risk_calculator
    if _risk_calculator is None:
        _risk_calculator = RiskCalculator()
    return _risk_calculator
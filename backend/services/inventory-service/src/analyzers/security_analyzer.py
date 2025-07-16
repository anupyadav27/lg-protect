#!/usr/bin/env python3
"""
Security Analyzer for LG-Protect Inventory System

Provides comprehensive security analysis for discovered AWS assets by integrating
with the existing compliance rules from the core-engine.
"""

import asyncio
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
import structlog
from pathlib import Path
import json
import importlib.util

from ..models.asset_models import AssetInfo, SecurityFinding, RiskScore
from ..utils.service_enablement_integration import get_service_enablement_integration

logger = structlog.get_logger(__name__)

class SecurityAnalyzer:
    """
    Advanced security analyzer that integrates with existing compliance rules
    """
    
    def __init__(self, core_engine_path: str = "/Users/apple/Desktop/lg-protect/core-engine"):
        self.core_engine_path = Path(core_engine_path)
        self.compliance_rules_path = self.core_engine_path / "compliance_rules"
        self.inventory_bridge_path = self.core_engine_path / "inventory_compliance_bridge"
        
        # Security analysis frameworks
        self.frameworks = [
            'cis-aws', 'nist-800-53', 'iso-27001', 'pci-dss', 
            'hipaa', 'gdpr', 'sox', 'fedramp'
        ]
        
        # Risk scoring weights
        self.risk_weights = {
            'encryption': 0.25,
            'access_control': 0.20,
            'network_security': 0.15,
            'logging_monitoring': 0.15,
            'configuration': 0.10,
            'backup_recovery': 0.10,
            'compliance': 0.05
        }
        
        # Severity multipliers
        self.severity_multipliers = {
            'critical': 1.0,
            'high': 0.8,
            'medium': 0.6,
            'low': 0.4,
            'info': 0.2
        }
        
        self._load_compliance_bridge()
        
    def _load_compliance_bridge(self):
        """Load the existing inventory-compliance bridge"""
        try:
            # Import the existing bridge
            bridge_init_file = self.inventory_bridge_path / "__init__.py"
            if bridge_init_file.exists():
                spec = importlib.util.spec_from_file_location(
                    "inventory_compliance_bridge", 
                    bridge_init_file
                )
                self.bridge_module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(self.bridge_module)
                
                logger.info("compliance_bridge_loaded", 
                           path=str(self.inventory_bridge_path))
            else:
                logger.warning("compliance_bridge_not_found", 
                              path=str(bridge_init_file))
                self.bridge_module = None
                
        except Exception as e:
            logger.error("failed_to_load_compliance_bridge", error=str(e))
            self.bridge_module = None
    
    async def analyze_asset_security(self, asset: AssetInfo, 
                                   frameworks: Optional[List[str]] = None) -> Tuple[List[SecurityFinding], RiskScore]:
        """
        Perform comprehensive security analysis on a single asset
        """
        try:
            frameworks = frameworks or self.frameworks
            
            logger.debug("analyzing_asset_security", 
                        asset_id=asset.resource_id,
                        service=asset.service,
                        frameworks=frameworks)
            
            # 1. Service-specific security analysis
            service_findings = await self._analyze_service_specific_security(asset)
            
            # 2. Cross-service security analysis
            cross_service_findings = await self._analyze_cross_service_security(asset)
            
            # 3. Compliance framework analysis
            compliance_findings = await self._analyze_compliance_frameworks(asset, frameworks)
            
            # 4. Configuration drift analysis
            drift_findings = await self._analyze_configuration_drift(asset)
            
            # Combine all findings
            all_findings = service_findings + cross_service_findings + compliance_findings + drift_findings
            
            # 5. Calculate comprehensive risk score
            risk_score = await self._calculate_risk_score(asset, all_findings)
            
            logger.info("asset_security_analysis_completed",
                       asset_id=asset.resource_id,
                       findings_count=len(all_findings),
                       risk_score=risk_score.overall_score)
            
            return all_findings, risk_score
            
        except Exception as e:
            logger.error("asset_security_analysis_failed",
                        asset_id=asset.resource_id,
                        error=str(e))
            return [], RiskScore(overall_score=0.0, category_scores={})
    
    async def analyze_bulk_assets(self, assets: List[AssetInfo], 
                                frameworks: Optional[List[str]] = None) -> Dict[str, Tuple[List[SecurityFinding], RiskScore]]:
        """
        Perform security analysis on multiple assets efficiently
        """
        results = {}
        
        try:
            logger.info("bulk_security_analysis_started",
                       asset_count=len(assets),
                       frameworks=frameworks or self.frameworks)
            
            # Group assets by service for efficient batch processing
            assets_by_service = {}
            for asset in assets:
                if asset.service not in assets_by_service:
                    assets_by_service[asset.service] = []
                assets_by_service[asset.service].append(asset)
            
            # Analyze each service group
            for service, service_assets in assets_by_service.items():
                logger.info("analyzing_service_batch",
                           service=service,
                           asset_count=len(service_assets))
                
                # Parallel analysis within service group
                tasks = []
                for asset in service_assets:
                    task = self.analyze_asset_security(asset, frameworks)
                    tasks.append((asset.resource_id, task))
                
                # Execute with controlled concurrency
                semaphore = asyncio.Semaphore(10)  # Limit concurrent analyses
                
                async def analyze_with_semaphore(asset_id, task):
                    async with semaphore:
                        return asset_id, await task
                
                batch_tasks = [analyze_with_semaphore(aid, task) for aid, task in tasks]
                batch_results = await asyncio.gather(*batch_tasks, return_exceptions=True)
                
                # Process results
                for result in batch_results:
                    if isinstance(result, Exception):
                        logger.error("batch_analysis_item_failed", error=str(result))
                        continue
                    
                    asset_id, (findings, risk_score) = result
                    results[asset_id] = (findings, risk_score)
            
            logger.info("bulk_security_analysis_completed",
                       total_assets=len(assets),
                       successful_analyses=len(results))
            
        except Exception as e:
            logger.error("bulk_security_analysis_failed", error=str(e))
        
        return results
    
    async def _analyze_service_specific_security(self, asset: AssetInfo) -> List[SecurityFinding]:
        """Analyze service-specific security configurations"""
        findings = []
        
        try:
            if asset.service == 's3':
                findings.extend(await self._analyze_s3_security(asset))
            elif asset.service == 'ec2':
                findings.extend(await self._analyze_ec2_security(asset))
            elif asset.service == 'rds':
                findings.extend(await self._analyze_rds_security(asset))
            elif asset.service == 'lambda':
                findings.extend(await self._analyze_lambda_security(asset))
            elif asset.service == 'iam':
                findings.extend(await self._analyze_iam_security(asset))
            elif asset.service == 'kms':
                findings.extend(await self._analyze_kms_security(asset))
            elif asset.service == 'vpc':
                findings.extend(await self._analyze_vpc_security(asset))
            elif asset.service == 'cloudtrail':
                findings.extend(await self._analyze_cloudtrail_security(asset))
            
            # Add generic security checks for all services
            findings.extend(await self._analyze_generic_security(asset))
            
        except Exception as e:
            logger.error("service_specific_analysis_failed",
                        service=asset.service,
                        asset_id=asset.resource_id,
                        error=str(e))
        
        return findings
    
    async def _analyze_s3_security(self, asset: AssetInfo) -> List[SecurityFinding]:
        """Comprehensive S3 security analysis"""
        findings = []
        config = asset.configuration
        
        # Public access analysis
        if config.get('PublicAccessBlockConfiguration'):
            pab = config['PublicAccessBlockConfiguration']
            if not all([
                pab.get('BlockPublicAcls', False),
                pab.get('IgnorePublicAcls', False),
                pab.get('BlockPublicPolicy', False),
                pab.get('RestrictPublicBuckets', False)
            ]):
                findings.append(SecurityFinding(
                    finding_type="access_control",
                    severity="high",
                    title="S3 bucket allows public access",
                    description="Bucket does not have all public access blocks enabled",
                    resource_id=asset.resource_id,
                    compliance_frameworks=["cis-aws", "nist-800-53"],
                    remediation="Enable all public access block settings"
                ))
        
        # Encryption analysis
        encryption_config = config.get('ServerSideEncryptionConfiguration', {})
        if not encryption_config:
            findings.append(SecurityFinding(
                finding_type="encryption",
                severity="high",
                title="S3 bucket not encrypted",
                description="Bucket does not have server-side encryption enabled",
                resource_id=asset.resource_id,
                compliance_frameworks=["pci-dss", "hipaa", "gdpr"],
                remediation="Enable server-side encryption with KMS"
            ))
        
        # Versioning analysis
        if not config.get('Versioning', {}).get('Status') == 'Enabled':
            findings.append(SecurityFinding(
                finding_type="backup_recovery",
                severity="medium",
                title="S3 bucket versioning disabled",
                description="Bucket does not have versioning enabled",
                resource_id=asset.resource_id,
                compliance_frameworks=["cis-aws"],
                remediation="Enable bucket versioning for data protection"
            ))
        
        # Logging analysis
        if not config.get('LoggingConfiguration'):
            findings.append(SecurityFinding(
                finding_type="logging_monitoring",
                severity="medium",
                title="S3 access logging disabled",
                description="Bucket does not have access logging enabled",
                resource_id=asset.resource_id,
                compliance_frameworks=["cis-aws", "nist-800-53"],
                remediation="Enable access logging to monitor bucket access"
            ))
        
        return findings
    
    async def _analyze_ec2_security(self, asset: AssetInfo) -> List[SecurityFinding]:
        """Comprehensive EC2 security analysis"""
        findings = []
        config = asset.configuration
        
        # Security group analysis
        security_groups = config.get('SecurityGroups', [])
        for sg in security_groups:
            # Check for overly permissive rules
            for rule in sg.get('IpPermissions', []):
                for ip_range in rule.get('IpRanges', []):
                    if ip_range.get('CidrIp') == '0.0.0.0/0':
                        findings.append(SecurityFinding(
                            finding_type="network_security",
                            severity="critical",
                            title="EC2 instance allows unrestricted access",
                            description=f"Security group allows access from 0.0.0.0/0 on port {rule.get('FromPort', 'all')}",
                            resource_id=asset.resource_id,
                            compliance_frameworks=["cis-aws", "nist-800-53"],
                            remediation="Restrict security group rules to specific IP ranges"
                        ))
        
        # IMDSv2 analysis
        metadata_options = config.get('MetadataOptions', {})
        if metadata_options.get('HttpTokens') != 'required':
            findings.append(SecurityFinding(
                finding_type="configuration",
                severity="high",
                title="EC2 instance not using IMDSv2",
                description="Instance metadata service v2 is not enforced",
                resource_id=asset.resource_id,
                compliance_frameworks=["cis-aws"],
                remediation="Enforce IMDSv2 by setting HttpTokens to required"
            ))
        
        # EBS encryption analysis
        for device in config.get('BlockDeviceMappings', []):
            ebs = device.get('Ebs', {})
            if not ebs.get('Encrypted', False):
                findings.append(SecurityFinding(
                    finding_type="encryption",
                    severity="high",
                    title="EC2 EBS volume not encrypted",
                    description=f"EBS volume {ebs.get('VolumeId', 'unknown')} is not encrypted",
                    resource_id=asset.resource_id,
                    compliance_frameworks=["pci-dss", "hipaa"],
                    remediation="Enable EBS encryption for all volumes"
                ))
        
        return findings
    
    async def _analyze_rds_security(self, asset: AssetInfo) -> List[SecurityFinding]:
        """Comprehensive RDS security analysis"""
        findings = []
        config = asset.configuration
        
        # Encryption analysis
        if not config.get('StorageEncrypted', False):
            findings.append(SecurityFinding(
                finding_type="encryption",
                severity="critical",
                title="RDS instance not encrypted",
                description="RDS instance does not have storage encryption enabled",
                resource_id=asset.resource_id,
                compliance_frameworks=["pci-dss", "hipaa", "gdpr"],
                remediation="Enable storage encryption for RDS instance"
            ))
        
        # Public accessibility analysis
        if config.get('PubliclyAccessible', False):
            findings.append(SecurityFinding(
                finding_type="network_security",
                severity="critical",
                title="RDS instance publicly accessible",
                description="RDS instance is accessible from the internet",
                resource_id=asset.resource_id,
                compliance_frameworks=["cis-aws", "nist-800-53"],
                remediation="Disable public accessibility for RDS instance"
            ))
        
        # Backup analysis
        if config.get('BackupRetentionPeriod', 0) < 7:
            findings.append(SecurityFinding(
                finding_type="backup_recovery",
                severity="medium",
                title="RDS backup retention insufficient",
                description=f"Backup retention period is {config.get('BackupRetentionPeriod', 0)} days",
                resource_id=asset.resource_id,
                compliance_frameworks=["cis-aws"],
                remediation="Set backup retention period to at least 7 days"
            ))
        
        return findings
    
    async def _analyze_lambda_security(self, asset: AssetInfo) -> List[SecurityFinding]:
        """Comprehensive Lambda security analysis"""
        findings = []
        config = asset.configuration
        
        # Runtime analysis
        runtime = config.get('Runtime', '')
        deprecated_runtimes = [
            'python2.7', 'python3.6', 'nodejs8.10', 'nodejs10.x',
            'dotnetcore2.1', 'ruby2.5', 'go1.x'
        ]
        
        if runtime in deprecated_runtimes:
            findings.append(SecurityFinding(
                finding_type="configuration",
                severity="high",
                title="Lambda using deprecated runtime",
                description=f"Function uses deprecated runtime: {runtime}",
                resource_id=asset.resource_id,
                compliance_frameworks=["cis-aws"],
                remediation="Update to a supported runtime version"
            ))
        
        # Environment variables analysis
        env_vars = config.get('Environment', {}).get('Variables', {})
        for key, value in env_vars.items():
            if any(keyword in key.lower() for keyword in ['password', 'secret', 'key', 'token']):
                findings.append(SecurityFinding(
                    finding_type="configuration",
                    severity="medium",
                    title="Lambda may contain sensitive data in environment variables",
                    description=f"Environment variable '{key}' may contain sensitive information",
                    resource_id=asset.resource_id,
                    compliance_frameworks=["gdpr", "pci-dss"],
                    remediation="Use AWS Systems Manager Parameter Store or Secrets Manager"
                ))
        
        return findings
    
    async def _analyze_iam_security(self, asset: AssetInfo) -> List[SecurityFinding]:
        """Comprehensive IAM security analysis"""
        findings = []
        config = asset.configuration
        
        # Policy analysis for overly permissive policies
        if asset.resource_type == 'policy':
            policy_doc = config.get('PolicyDocument', {})
            statements = policy_doc.get('Statement', [])
            
            for statement in statements:
                if isinstance(statement, dict):
                    effect = statement.get('Effect', '')
                    actions = statement.get('Action', [])
                    resources = statement.get('Resource', [])
                    
                    # Check for wildcard permissions
                    if effect == 'Allow':
                        if '*' in actions or (isinstance(actions, list) and '*' in actions):
                            if '*' in resources or (isinstance(resources, list) and '*' in resources):
                                findings.append(SecurityFinding(
                                    finding_type="access_control",
                                    severity="critical",
                                    title="IAM policy allows full access",
                                    description="Policy grants * actions on * resources",
                                    resource_id=asset.resource_id,
                                    compliance_frameworks=["cis-aws", "nist-800-53"],
                                    remediation="Apply principle of least privilege"
                                ))
        
        # User analysis
        elif asset.resource_type == 'user':
            # Check for console access without MFA
            if not config.get('MfaActive', False):
                findings.append(SecurityFinding(
                    finding_type="access_control",
                    severity="high",
                    title="IAM user without MFA",
                    description="User does not have MFA enabled",
                    resource_id=asset.resource_id,
                    compliance_frameworks=["cis-aws", "nist-800-53"],
                    remediation="Enable MFA for all IAM users"
                ))
        
        return findings
    
    async def _analyze_generic_security(self, asset: AssetInfo) -> List[SecurityFinding]:
        """Generic security analysis applicable to all resources"""
        findings = []
        
        # Tags analysis
        tags = asset.tags or []
        required_tags = ['Environment', 'Owner', 'Project', 'CostCenter']
        missing_tags = []
        
        tag_keys = [tag.get('Key', '') for tag in tags]
        for required_tag in required_tags:
            if required_tag not in tag_keys:
                missing_tags.append(required_tag)
        
        if missing_tags:
            findings.append(SecurityFinding(
                finding_type="configuration",
                severity="low",
                title="Resource missing required tags",
                description=f"Missing tags: {', '.join(missing_tags)}",
                resource_id=asset.resource_id,
                compliance_frameworks=["governance"],
                remediation="Add required tags for resource management"
            ))
        
        # Age analysis
        if asset.created_date:
            try:
                if isinstance(asset.created_date, str):
                    created_date = datetime.fromisoformat(asset.created_date.replace('Z', '+00:00'))
                else:
                    created_date = asset.created_date
                
                age_days = (datetime.now() - created_date.replace(tzinfo=None)).days
                
                if age_days > 365:  # Resources older than 1 year
                    findings.append(SecurityFinding(
                        finding_type="configuration",
                        severity="info",
                        title="Long-running resource",
                        description=f"Resource has been running for {age_days} days",
                        resource_id=asset.resource_id,
                        compliance_frameworks=["governance"],
                        remediation="Review if resource is still needed"
                    ))
            except Exception as e:
                logger.debug("age_analysis_failed", asset_id=asset.resource_id, error=str(e))
        
        return findings
    
    async def _analyze_cross_service_security(self, asset: AssetInfo) -> List[SecurityFinding]:
        """Analyze security implications across services"""
        findings = []
        
        # This would be enhanced with actual cross-service analysis
        # For now, providing framework for future implementation
        
        return findings
    
    async def _analyze_compliance_frameworks(self, asset: AssetInfo, frameworks: List[str]) -> List[SecurityFinding]:
        """Analyze asset against specific compliance frameworks using existing bridge"""
        findings = []
        
        try:
            if self.bridge_module:
                # Use the existing inventory-compliance bridge
                # This would integrate with your 20,000+ compliance rules
                
                # Mock integration - replace with actual bridge call
                for framework in frameworks:
                    # Example of how this would integrate
                    compliance_result = await self._check_compliance_framework(asset, framework)
                    if compliance_result:
                        findings.extend(compliance_result)
            
        except Exception as e:
            logger.error("compliance_framework_analysis_failed",
                        asset_id=asset.resource_id,
                        frameworks=frameworks,
                        error=str(e))
        
        return findings
    
    async def _check_compliance_framework(self, asset: AssetInfo, framework: str) -> List[SecurityFinding]:
        """Check asset against specific compliance framework"""
        # This would integrate with your existing compliance engine
        # Placeholder for actual implementation
        return []
    
    async def _analyze_configuration_drift(self, asset: AssetInfo) -> List[SecurityFinding]:
        """Analyze configuration drift from security baselines"""
        findings = []
        
        # Placeholder for configuration drift analysis
        # This would compare current config against security baselines
        
        return findings
    
    async def _calculate_risk_score(self, asset: AssetInfo, findings: List[SecurityFinding]) -> RiskScore:
        """Calculate comprehensive risk score based on findings"""
        try:
            category_scores = {
                'encryption': 100.0,
                'access_control': 100.0,
                'network_security': 100.0,
                'logging_monitoring': 100.0,
                'configuration': 100.0,
                'backup_recovery': 100.0,
                'compliance': 100.0
            }
            
            # Reduce scores based on findings
            for finding in findings:
                category = finding.finding_type
                severity_impact = self.severity_multipliers.get(finding.severity, 0.5)
                
                if category in category_scores:
                    # Reduce score based on severity (max 50 points per finding)
                    reduction = min(50.0, severity_impact * 50.0)
                    category_scores[category] = max(0.0, category_scores[category] - reduction)
            
            # Calculate overall score using weights
            overall_score = sum(
                score * self.risk_weights.get(category, 0.0)
                for category, score in category_scores.items()
            )
            
            return RiskScore(
                overall_score=round(overall_score, 2),
                category_scores=category_scores,
                findings_count=len(findings),
                critical_findings=len([f for f in findings if f.severity == 'critical']),
                high_findings=len([f for f in findings if f.severity == 'high']),
                calculated_at=datetime.now().isoformat()
            )
            
        except Exception as e:
            logger.error("risk_score_calculation_failed",
                        asset_id=asset.resource_id,
                        error=str(e))
            return RiskScore(overall_score=0.0, category_scores={})
    
    def get_security_analysis_summary(self, analysis_results: Dict[str, Tuple[List[SecurityFinding], RiskScore]]) -> Dict[str, Any]:
        """Generate summary of security analysis results"""
        try:
            total_assets = len(analysis_results)
            total_findings = sum(len(findings) for findings, _ in analysis_results.values())
            
            severity_counts = {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'info': 0
            }
            
            category_counts = {}
            framework_counts = {}
            
            risk_scores = []
            
            for asset_id, (findings, risk_score) in analysis_results.items():
                risk_scores.append(risk_score.overall_score)
                
                for finding in findings:
                    severity_counts[finding.severity] += 1
                    
                    if finding.finding_type not in category_counts:
                        category_counts[finding.finding_type] = 0
                    category_counts[finding.finding_type] += 1
                    
                    for framework in finding.compliance_frameworks:
                        if framework not in framework_counts:
                            framework_counts[framework] = 0
                        framework_counts[framework] += 1
            
            avg_risk_score = sum(risk_scores) / len(risk_scores) if risk_scores else 0.0
            
            return {
                'summary': {
                    'total_assets_analyzed': total_assets,
                    'total_findings': total_findings,
                    'average_risk_score': round(avg_risk_score, 2),
                    'analysis_timestamp': datetime.now().isoformat()
                },
                'severity_distribution': severity_counts,
                'category_distribution': category_counts,
                'compliance_framework_distribution': framework_counts,
                'risk_score_distribution': {
                    'min': min(risk_scores) if risk_scores else 0.0,
                    'max': max(risk_scores) if risk_scores else 0.0,
                    'avg': avg_risk_score,
                    'scores': risk_scores
                }
            }
            
        except Exception as e:
            logger.error("security_analysis_summary_failed", error=str(e))
            return {}

# Global analyzer instance
_security_analyzer = None

def get_security_analyzer() -> SecurityAnalyzer:
    """Get the global security analyzer instance"""
    global _security_analyzer
    if _security_analyzer is None:
        _security_analyzer = SecurityAnalyzer()
    return _security_analyzer
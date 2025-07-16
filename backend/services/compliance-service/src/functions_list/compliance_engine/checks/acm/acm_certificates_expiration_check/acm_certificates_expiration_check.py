import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..', 'utils'))
from reporting import (
    BaseCheck, CheckReport, CheckMetadata, CheckStatus, 
    Severity, ComplianceStandard
)

from ..acm_client import get_acm_client


class acm_certificates_expiration_check(BaseCheck):
    """Check if ACM certificates are about to expire"""
    
    def _get_metadata(self) -> CheckMetadata:
        """Get check metadata"""
        return CheckMetadata(
            check_id="acm_certificates_expiration_check",
            check_name="ACM Certificates Expiration Check",
            description="Check if ACM certificates are about to expire in specific days or less",
            severity=Severity.HIGH,
            compliance_standard=ComplianceStandard.AWS_FOUNDATIONAL_SECURITY_BEST_PRACTICES,
            category="Data Protection",
            tags=["acm", "certificates", "expiration", "availability", "security"],
            remediation="Monitor certificate expiration and take automated action to renew, replace or remove. Use AWS Config managed rule: acm-certificate-expiration-check",
            references=[
                "https://docs.aws.amazon.com/config/latest/developerguide/acm-certificate-expiration-check.html",
                "https://docs.aws.amazon.com/acm/latest/userguide/acm-certificate.html"
            ]
        )
    
    def execute(self) -> list[CheckReport]:
        """Check all certificates for expiration"""
        findings = []
        
        # Get ACM client
        acm_client = get_acm_client()
        
        # Get expiration threshold from configuration (default 30 days)
        expiration_threshold = 30  # days
        
        # Check each certificate
        for certificate in acm_client.certificates.values():
            if self._should_check_certificate(certificate):
                report = self._check_certificate_expiration(certificate, expiration_threshold)
                findings.append(report)
        
                return findings
    
    def _should_check_certificate(self, certificate) -> bool:
        """Should we check this certificate?"""
        # Check if certificate is in use OR if we should scan unused services
        return certificate.in_use or True  # Always check for now
    
    def _check_certificate_expiration(self, certificate, threshold: int) -> CheckReport:
        """Check if a single certificate is expiring soon"""
        
        # Determine severity based on expiration status
        if certificate.expiration_days < 0:
            # Certificate has already expired - HIGH severity
            severity = Severity.HIGH
            status = CheckStatus.FAIL
            status_extended = (
                f"ACM Certificate {certificate.id} for {certificate.name} "
                f"has expired ({abs(certificate.expiration_days)} days ago)."
            )
        elif certificate.expiration_days <= threshold:
            # Certificate is about to expire - MEDIUM severity
            severity = Severity.MEDIUM
            status = CheckStatus.FAIL
            status_extended = (
                f"ACM Certificate {certificate.id} for {certificate.name} "
                f"is about to expire in {certificate.expiration_days} days."
            )
        else:
            # Certificate is not expiring soon - LOW severity
            severity = Severity.LOW
            status = CheckStatus.PASS
            status_extended = (
                f"ACM Certificate {certificate.id} for {certificate.name} "
                f"expires in {certificate.expiration_days} days."
            )
        
        # Create report for this certificate
        report = CheckReport(
            status=status,
            status_extended=status_extended,
            resource=certificate,
            metadata=self.metadata,
            region=certificate.region,
            evidence={
                "certificate_id": certificate.id,
                "certificate_name": certificate.name,
                "expiration_days": certificate.expiration_days,
                "is_expired": certificate.is_expired,
                "is_expiring_soon": certificate.is_expiring_soon,
                "expiration_threshold": threshold,
                "in_use": certificate.in_use
            }
        )
        
        return report
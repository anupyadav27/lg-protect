import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..', 'utils'))
from reporting import (
    BaseCheck, CheckReport, CheckMetadata, CheckStatus, 
    Severity, ComplianceStandard
)

from ..acm_client import get_acm_client


class acm_certificates_transparency_logs_enabled(BaseCheck):
    """Check if ACM certificates have Certificate Transparency logging enabled"""
    
    def _get_metadata(self) -> CheckMetadata:
        """Get check metadata"""
        return CheckMetadata(
            check_id="acm_certificates_transparency_logs_enabled",
            check_name="ACM Certificates Transparency Logs Enabled",
            description="Check if ACM certificates have Certificate Transparency logging enabled",
            severity=Severity.MEDIUM,
            compliance_standard=ComplianceStandard.AWS_FOUNDATIONAL_SECURITY_BEST_PRACTICES,
            category="Logging and Monitoring",
            tags=["acm", "certificates", "transparency", "logging", "security"],
            remediation="Enable Certificate Transparency logging for ACM certificates to improve security monitoring and detect unauthorized certificate issuance",
            references=[
                "https://aws.amazon.com/blogs/security/how-to-get-ready-for-certificate-transparency/",
                "https://docs.aws.amazon.com/acm/latest/userguide/acm-certificate.html"
            ]
        )
    
    def execute(self) -> list[CheckReport]:
        """Check all certificates for transparency logging"""
        findings = []
        
        # Get ACM client
        acm_client = get_acm_client()
        
        # Check each certificate
        for certificate in acm_client.certificates.values():
            if self._should_check_certificate(certificate):
                report = self._check_transparency_logging(certificate)
                findings.append(report)
        
                return findings
    
    def _should_check_certificate(self, certificate) -> bool:
        """Should we check this certificate?"""
        # Check if certificate is in use OR if we should scan unused services
        return certificate.in_use or True  # Always check for now
    
    def _check_transparency_logging(self, certificate) -> CheckReport:
        """Check if a single certificate has transparency logging enabled"""
        
        # Check certificate type and transparency logging
        if certificate.type == "IMPORTED":
            # Imported certificates don't support transparency logging - PASS
            status = CheckStatus.PASS
            status_extended = (
                f"ACM Certificate {certificate.id} for {certificate.name} is imported "
                f"and does not support Certificate Transparency logging."
            )
        else:
            # For non-imported certificates, check transparency logging
            if certificate.transparency_logging:
                # Transparency logging is enabled - PASS
                status = CheckStatus.PASS
                status_extended = (
                    f"ACM Certificate {certificate.id} for {certificate.name} "
                    f"has Certificate Transparency logging enabled."
                )
            else:
                # Transparency logging is disabled - FAIL
                status = CheckStatus.FAIL
                status_extended = (
                    f"ACM Certificate {certificate.id} for {certificate.name} "
                    f"has Certificate Transparency logging disabled."
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
                "certificate_type": certificate.type,
                "transparency_logging": certificate.transparency_logging,
                "in_use": certificate.in_use
            }
        )
        
        return report
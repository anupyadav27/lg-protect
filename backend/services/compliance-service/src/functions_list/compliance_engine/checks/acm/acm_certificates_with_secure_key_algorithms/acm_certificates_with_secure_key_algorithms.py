import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..', 'utils'))
from reporting import (
    BaseCheck, CheckReport, CheckMetadata, CheckStatus, 
    Severity, ComplianceStandard
)

from ..acm_client import get_acm_client


class acm_certificates_with_secure_key_algorithms(BaseCheck):
    """Check if ACM certificates are using secure key algorithms"""
    
    def _get_metadata(self) -> CheckMetadata:
        """Get check metadata"""
        return CheckMetadata(
            check_id="acm_certificates_with_secure_key_algorithms",
            check_name="ACM Certificates with Secure Key Algorithms",
            description="Ensure ACM certificates are using secure key algorithms (RSA 2048+ or EC curves)",
            severity=Severity.MEDIUM,
            compliance_standard=ComplianceStandard.AWS_FOUNDATIONAL_SECURITY_BEST_PRACTICES,
            category="Cryptography",
            tags=["acm", "certificates", "cryptography", "security"],
            remediation="Replace certificates using RSA_1024 or smaller key sizes with RSA_2048 or larger, or use EC curves",
            references=[
                "https://docs.aws.amazon.com/acm/latest/userguide/acm-certificate.html",
                "https://aws.amazon.com/blogs/security/how-to-prepare-for-aws-move-to-2048-bit-rsa-certificate-keys/"
            ]
        )
    
    def execute(self) -> list[CheckReport]:
        """Check all certificates for secure algorithms"""
        findings = []
        
        # Get ACM client
        acm_client = get_acm_client()
        
        # Get list of insecure algorithms from configuration
        insecure_algorithms = ["RSA_1024", "RSA_512"]  # Add more as needed
        
        # Check each certificate
        for certificate in acm_client.certificates.values():
            if self._should_check_certificate(certificate):
                report = self._check_certificate(certificate, insecure_algorithms)
                findings.append(report)
        
                return findings
    
    def _should_check_certificate(self, certificate) -> bool:
        """Should we check this certificate?"""
        # Check if certificate is in use OR if we should scan unused services
        return certificate.in_use or True  # Always check for now
    
    def _check_certificate(self, certificate, insecure_algorithms: list) -> CheckReport:
        """Check if a single certificate uses secure algorithm"""
        
        # Determine status and message
        if certificate.key_algorithm in insecure_algorithms:
            status = CheckStatus.FAIL
            status_extended = (
                f"ACM Certificate {certificate.id} for {certificate.name} "
                f"does not use a secure key algorithm ({certificate.key_algorithm})."
            )
        else:
            status = CheckStatus.PASS
            status_extended = (
                f"ACM Certificate {certificate.id} for {certificate.name} "
                f"uses a secure key algorithm ({certificate.key_algorithm})."
            )
        
        # Create report for this certificate
        report = CheckReport(
            status=status,
            status_extended=status_extended,
            resource=certificate,
            metadata=self.metadata,
            region=certificate.region,
            evidence={
                "key_algorithm": certificate.key_algorithm,
                "certificate_id": certificate.id,
                "certificate_name": certificate.name,
                "in_use": certificate.in_use,
                "insecure_algorithms": insecure_algorithms
            }
        )
        
        return report
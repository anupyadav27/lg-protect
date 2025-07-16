from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.acm.acm_client import acm_client


class acm_certificates_transparency_logs_enabled(Check):
    """Simple check: Are ACM certificates using transparency logging?"""
    
    def execute(self):
        """Check all certificates for transparency logging"""
        findings = []
        
        # Check each certificate
        for certificate in acm_client.certificates.values():
            if self._should_check_certificate(certificate):
                report = self._check_transparency_logging(certificate)
                findings.append(report)
        
        return findings
    
    def _should_check_certificate(self, certificate) -> bool:
        """Should we check this certificate?"""
        return certificate.in_use or acm_client.provider.scan_unused_services
    
    def _check_transparency_logging(self, certificate) -> Check_Report_AWS:
        """Check if a single certificate has transparency logging enabled"""
        
        # Create report for this certificate
        report = Check_Report_AWS(
            metadata=self.metadata(), 
            resource=certificate
        )
        
        # Check certificate type and transparency logging
        if certificate.type == "IMPORTED":
            # Imported certificates don't support transparency logging - PASS
            report.status = "PASS"
            report.status_extended = (
                f"ACM Certificate {certificate.id} for {certificate.name} is imported."
            )
        else:
            # For non-imported certificates, check transparency logging
            if certificate.transparency_logging:
                # Transparency logging is enabled - PASS
                report.status = "PASS"
                report.status_extended = (
                    f"ACM Certificate {certificate.id} for {certificate.name} "
                    f"has Certificate Transparency logging enabled."
                )
            else:
                # Transparency logging is disabled - FAIL
                report.status = "FAIL"
                report.status_extended = (
                    f"ACM Certificate {certificate.id} for {certificate.name} "
                    f"has Certificate Transparency logging disabled."
                )
        
        return report
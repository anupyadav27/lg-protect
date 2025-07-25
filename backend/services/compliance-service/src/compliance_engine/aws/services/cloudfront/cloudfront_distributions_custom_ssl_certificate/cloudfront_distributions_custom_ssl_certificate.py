from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.cloudfront.cloudfront_client import (
    cloudfront_client,
)


class cloudfront_distributions_custom_ssl_certificate(Check):
    def execute(self):
        findings = []
        for distribution in cloudfront_client.distributions.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=distribution)
            report.status = "PASS"
            report.status_extended = f"CloudFront Distribution {distribution.id} is using a custom SSL/TLS certificate."

            if distribution.default_certificate:
                report.status = "FAIL"
                report.status_extended = f"CloudFront Distribution {distribution.id} is using the default SSL/TLS certificate."

            findings.append(report)

        return findings

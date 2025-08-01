from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.cloudfront.cloudfront_client import (
    cloudfront_client,
)
from prowler.providers.aws.services.cloudfront.cloudfront_service import (
    OriginsSSLProtocols,
)


class cloudfront_distributions_using_deprecated_ssl_protocols(Check):
    def execute(self):
        findings = []
        for distribution in cloudfront_client.distributions.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=distribution)
            report.status = "PASS"
            report.status_extended = f"CloudFront Distribution {distribution.id} is not using a deprecated SSL protocol."

            bad_ssl_protocol = False
            for origin in distribution.origins:
                if origin.origin_ssl_protocols:
                    for ssl_protocol in origin.origin_ssl_protocols:
                        if ssl_protocol in (
                            OriginsSSLProtocols.SSLv3.value,
                            OriginsSSLProtocols.TLSv1.value,
                            OriginsSSLProtocols.TLSv1_1.value,
                        ):
                            bad_ssl_protocol = True
                            break

                if bad_ssl_protocol:
                    report.status = "FAIL"
                    report.status_extended = f"CloudFront Distribution {distribution.id} is using a deprecated SSL protocol."
                    break

            findings.append(report)

        return findings

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.route53.route53domains_client import (
    route53domains_client,
)


class route53_domains_transferlock_enabled(Check):
    def execute(self) -> Check_Report_AWS:
        findings = []

        for domain in route53domains_client.domains.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=domain)
            if domain.status_list and "clientTransferProhibited" in domain.status_list:
                report.status = "PASS"
                report.status_extended = (
                    f"Transfer Lock is enabled for the {domain.name} domain."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Transfer Lock is disabled for the {domain.name} domain."
                )

            findings.append(report)

        return findings

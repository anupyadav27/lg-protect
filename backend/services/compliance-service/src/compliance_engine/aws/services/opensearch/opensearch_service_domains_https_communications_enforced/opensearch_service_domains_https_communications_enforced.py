from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.opensearch.opensearch_client import (
    opensearch_client,
)


class opensearch_service_domains_https_communications_enforced(Check):
    def execute(self):
        findings = []
        for domain in opensearch_client.opensearch_domains.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=domain)
            report.status = "PASS"
            report.status_extended = (
                f"Opensearch domain {domain.name} has enforce HTTPS enabled."
            )
            if not domain.enforce_https:
                report.status = "FAIL"
                report.status_extended = f"Opensearch domain {domain.name} does not have enforce HTTPS enabled."

            findings.append(report)

        return findings

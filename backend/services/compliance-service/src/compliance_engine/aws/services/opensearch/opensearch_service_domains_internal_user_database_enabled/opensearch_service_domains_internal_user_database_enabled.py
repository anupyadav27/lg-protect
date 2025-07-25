from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.opensearch.opensearch_client import (
    opensearch_client,
)


class opensearch_service_domains_internal_user_database_enabled(Check):
    def execute(self):
        findings = []
        for domain in opensearch_client.opensearch_domains.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=domain)
            report.status = "PASS"
            report.status_extended = f"Opensearch domain {domain.name} does not have internal user database enabled."
            if domain.internal_user_database:
                report.status = "FAIL"
                report.status_extended = f"Opensearch domain {domain.name} has internal user database enabled."

            findings.append(report)

        return findings

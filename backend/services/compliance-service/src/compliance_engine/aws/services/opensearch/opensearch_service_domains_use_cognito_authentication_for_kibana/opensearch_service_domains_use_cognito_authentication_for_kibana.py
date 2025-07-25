from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.opensearch.opensearch_client import (
    opensearch_client,
)


class opensearch_service_domains_use_cognito_authentication_for_kibana(Check):
    def execute(self):
        findings = []
        for domain in opensearch_client.opensearch_domains.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=domain)
            report.status = "PASS"
            report.status_extended = f"Opensearch domain {domain.name} has either Amazon Cognito or SAML authentication for Kibana enabled."
            if not domain.cognito_options and not domain.saml_enabled:
                report.status = "FAIL"
                report.status_extended = f"Opensearch domain {domain.name} has neither Amazon Cognito nor SAML authentication for Kibana enabled."

            findings.append(report)

        return findings

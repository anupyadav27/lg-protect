from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.networkfirewall.networkfirewall_client import (
    networkfirewall_client,
)


class networkfirewall_logging_enabled(Check):
    def execute(self):
        findings = []
        for firewall in networkfirewall_client.network_firewalls.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=firewall)
            report.status = "FAIL"
            report.status_extended = (
                f"Network Firewall {firewall.name} does not have logging enabled."
            )

            for configuration in firewall.logging_configuration:
                if configuration.log_type or configuration.log_destination:
                    report.status = "PASS"
                    report.status_extended = (
                        f"Network Firewall {firewall.name} has logging enabled."
                    )
                    break

            findings.append(report)

        return findings

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.networkfirewall.networkfirewall_client import (
    networkfirewall_client,
)


class networkfirewall_multi_az(Check):
    def execute(self):
        findings = []
        for firewall in networkfirewall_client.network_firewalls.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=firewall)
            report.status = "FAIL"
            report.status_extended = (
                f"Network Firewall {firewall.name} is not deployed across multiple AZ."
            )

            if len(firewall.subnet_mappings) > 1:
                report.status = "PASS"
                report.status_extended = (
                    f"Network Firewall {firewall.name} is deployed across multiple AZ."
                )

            findings.append(report)

        return findings

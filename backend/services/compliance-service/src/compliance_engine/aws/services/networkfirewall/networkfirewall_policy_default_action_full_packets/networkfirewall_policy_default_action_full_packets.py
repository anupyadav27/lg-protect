from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.networkfirewall.networkfirewall_client import (
    networkfirewall_client,
)


class networkfirewall_policy_default_action_full_packets(Check):
    def execute(self):
        findings = []
        for firewall in networkfirewall_client.network_firewalls.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=firewall)
            report.status = "FAIL"
            report.status_extended = f"Network Firewall {firewall.name} policy does not drop or forward full packets by default."

            if (
                "aws:drop" in firewall.default_stateless_actions
                or "aws:forward_to_sfe" in firewall.default_stateless_actions
            ):
                report.status = "PASS"
                report.status_extended = f"Network Firewall {firewall.name} policy does drop or forward full packets by default."

            findings.append(report)

        return findings

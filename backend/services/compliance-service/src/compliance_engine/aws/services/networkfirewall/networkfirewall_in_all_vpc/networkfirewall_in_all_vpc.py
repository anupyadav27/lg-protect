from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.networkfirewall.networkfirewall_client import (
    networkfirewall_client,
)
from prowler.providers.aws.services.vpc.vpc_client import vpc_client


class networkfirewall_in_all_vpc(Check):
    def execute(self):
        findings = []
        for vpc in vpc_client.vpcs.values():
            if vpc_client.provider.scan_unused_services or vpc.in_use:
                report = Check_Report_AWS(metadata=self.metadata(), resource=vpc)
                report.status = "FAIL"
                report.status_extended = f"VPC {vpc.name if vpc.name else vpc.id} does not have Network Firewall enabled."
                for firewall in networkfirewall_client.network_firewalls.values():
                    if firewall.vpc_id == vpc.id:
                        report.status = "PASS"
                        report.status_extended = f"VPC {vpc.name if vpc.name else vpc.id} has Network Firewall enabled."
                        break

                findings.append(report)

        return findings

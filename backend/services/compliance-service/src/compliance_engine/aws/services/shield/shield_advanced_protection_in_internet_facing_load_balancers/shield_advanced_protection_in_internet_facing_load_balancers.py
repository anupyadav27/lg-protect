from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.elbv2.elbv2_client import elbv2_client
from prowler.providers.aws.services.shield.shield_client import shield_client


class shield_advanced_protection_in_internet_facing_load_balancers(Check):
    def execute(self):
        findings = []
        if shield_client.enabled:
            for elbv2_arn, elbv2 in elbv2_client.loadbalancersv2.items():
                if elbv2.type == "application" and elbv2.scheme == "internet-facing":
                    report = Check_Report_AWS(metadata=self.metadata(), resource=elbv2)
                    report.region = shield_client.region
                    report.status = "FAIL"
                    report.status_extended = f"ELBv2 ALB {elbv2.name} is not protected by AWS Shield Advanced."

                    for protection in shield_client.protections.values():
                        if elbv2_arn == protection.resource_arn:
                            report.status = "PASS"
                            report.status_extended = f"ELBv2 ALB {elbv2.name} is protected by AWS Shield Advanced."
                            break

                    findings.append(report)

        return findings

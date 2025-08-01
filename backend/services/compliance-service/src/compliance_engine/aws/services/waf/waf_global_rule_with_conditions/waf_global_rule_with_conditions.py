from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.waf.waf_client import waf_client


class waf_global_rule_with_conditions(Check):
    def execute(self):
        findings = []
        for rule in waf_client.rules.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=rule)
            report.status = "FAIL"
            report.status_extended = (
                f"AWS WAF Global Rule {rule.name} does not have any conditions."
            )

            if rule.predicates:
                report.status = "PASS"
                report.status_extended = (
                    f"AWS WAF Global Rule {rule.name} has at least one condition."
                )

            findings.append(report)

        return findings

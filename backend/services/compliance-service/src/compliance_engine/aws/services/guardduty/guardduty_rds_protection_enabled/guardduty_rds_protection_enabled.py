from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.guardduty.guardduty_client import guardduty_client


class guardduty_rds_protection_enabled(Check):
    def execute(self):
        findings = []
        for detector in guardduty_client.detectors:
            if detector.status:
                report = Check_Report_AWS(metadata=self.metadata(), resource=detector)
                report.status = "FAIL"
                report.status_extended = (
                    "GuardDuty detector does not have RDS Protection enabled."
                )
                if detector.rds_protection:
                    report.status = "PASS"
                    report.status_extended = (
                        "GuardDuty detector has RDS Protection enabled."
                    )
                findings.append(report)
        return findings

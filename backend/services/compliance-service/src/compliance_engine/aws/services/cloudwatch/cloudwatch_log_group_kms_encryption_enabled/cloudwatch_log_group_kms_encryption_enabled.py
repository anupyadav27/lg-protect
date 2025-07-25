from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.cloudwatch.logs_client import logs_client


class cloudwatch_log_group_kms_encryption_enabled(Check):
    def execute(self):
        findings = []
        if logs_client.log_groups:
            for log_group in logs_client.log_groups.values():
                report = Check_Report_AWS(metadata=self.metadata(), resource=log_group)
                if log_group.kms_id:
                    report.status = "PASS"
                    report.status_extended = f"Log Group {log_group.name} does have AWS KMS key {log_group.kms_id} associated."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"Log Group {log_group.name} does not have AWS KMS keys associated."
                findings.append(report)
        return findings

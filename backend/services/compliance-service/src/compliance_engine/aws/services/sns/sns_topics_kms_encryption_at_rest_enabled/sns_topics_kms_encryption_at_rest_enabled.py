from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.sns.sns_client import sns_client


class sns_topics_kms_encryption_at_rest_enabled(Check):
    def execute(self):
        findings = []
        for topic in sns_client.topics:
            report = Check_Report_AWS(metadata=self.metadata(), resource=topic)
            report.status = "PASS"
            report.status_extended = f"SNS topic {topic.name} is encrypted."
            if not topic.kms_master_key_id:
                report.status = "FAIL"
                report.status_extended = f"SNS topic {topic.name} is not encrypted."

            findings.append(report)

        return findings

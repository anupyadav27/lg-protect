from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.dms.dms_client import dms_client


class dms_instance_multi_az_enabled(Check):
    def execute(self):
        findings = []
        for instance in dms_client.instances:
            report = Check_Report_AWS(metadata=self.metadata(), resource=instance)
            report.status = "FAIL"
            report.status_extended = f"DMS Replication Instance {instance.id} does not have multi az enabled."
            if instance.multi_az:
                report.status = "PASS"
                report.status_extended = (
                    f"DMS Replication Instance {instance.id} has multi az enabled."
                )

            findings.append(report)

        return findings

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.dynamodb.dax_client import dax_client


class dynamodb_accelerator_cluster_encryption_enabled(Check):
    def execute(self):
        findings = []
        for cluster in dax_client.clusters:
            report = Check_Report_AWS(metadata=self.metadata(), resource=cluster)
            report.status = "FAIL"
            report.status_extended = (
                f"DAX cluster {cluster.name} does not have encryption at rest enabled."
            )
            if cluster.encryption:
                report.status = "PASS"
                report.status_extended = (
                    f"DAX cluster {cluster.name} has encryption at rest enabled."
                )
            findings.append(report)
        return findings

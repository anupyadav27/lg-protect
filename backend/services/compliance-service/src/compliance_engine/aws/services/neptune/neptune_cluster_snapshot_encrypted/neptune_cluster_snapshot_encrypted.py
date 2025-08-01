from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.neptune.neptune_client import neptune_client


class neptune_cluster_snapshot_encrypted(Check):
    def execute(self):
        findings = []
        for snapshot in neptune_client.db_cluster_snapshots:
            report = Check_Report_AWS(metadata=self.metadata(), resource=snapshot)
            report.status = "FAIL"
            report.status_extended = (
                f"Neptune Cluster Snapshot {snapshot.id} is not encrypted at rest."
            )
            if snapshot.encrypted:
                report.status = "PASS"
                report.status_extended = (
                    f"Neptune Cluster Snapshot {snapshot.id} is encrypted at rest."
                )

            findings.append(report)

        return findings

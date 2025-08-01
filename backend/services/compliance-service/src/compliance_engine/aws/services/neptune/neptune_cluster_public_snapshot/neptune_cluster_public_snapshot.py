from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.neptune.neptune_client import neptune_client


class neptune_cluster_public_snapshot(Check):
    def execute(self):
        findings = []
        for db_snap in neptune_client.db_cluster_snapshots:
            report = Check_Report_AWS(metadata=self.metadata(), resource=db_snap)
            if db_snap.public:
                report.status = "FAIL"
                report.status_extended = (
                    f"NeptuneDB Cluster Snapshot {db_snap.id} is public."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"NeptuneDB Cluster Snapshot {db_snap.id} is not shared publicly."
                )

            findings.append(report)

        return findings

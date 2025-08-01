from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.documentdb.documentdb_client import (
    documentdb_client,
)


class documentdb_cluster_multi_az_enabled(Check):
    def execute(self):
        findings = []
        for db_cluster in documentdb_client.db_clusters.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=db_cluster)
            report.status = "FAIL"
            report.status_extended = (
                f"DocumentDB Cluster {db_cluster.id} does not have Multi-AZ enabled."
            )
            if db_cluster.multi_az:
                report.status = "PASS"
                report.status_extended = (
                    f"DocumentDB Cluster {db_cluster.id} has Multi-AZ enabled."
                )

            findings.append(report)

        return findings

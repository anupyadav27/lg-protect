from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.documentdb.documentdb_client import (
    documentdb_client,
)


class documentdb_cluster_deletion_protection(Check):
    def execute(self):
        findings = []
        for cluster in documentdb_client.db_clusters.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=cluster)
            report.status = "FAIL"
            report.status_extended = f"DocumentDB Cluster {cluster.id} does not have deletion protection enabled."
            if cluster.deletion_protection:
                report.status = "PASS"
                report.status_extended = (
                    f"DocumentDB Cluster {cluster.id} has deletion protection enabled."
                )

            findings.append(report)

        return findings

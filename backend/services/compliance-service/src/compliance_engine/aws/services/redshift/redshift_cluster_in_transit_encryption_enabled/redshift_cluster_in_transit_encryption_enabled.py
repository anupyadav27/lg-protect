from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.redshift.redshift_client import redshift_client


class redshift_cluster_in_transit_encryption_enabled(Check):
    def execute(self):
        findings = []
        for cluster in redshift_client.clusters:
            report = Check_Report_AWS(metadata=self.metadata(), resource=cluster)
            report.status = "FAIL"
            report.status_extended = (
                f"Redshift Cluster {cluster.id} is not encrypted in transit."
            )
            if cluster.require_ssl:
                report.status = "PASS"
                report.status_extended = (
                    f"Redshift Cluster {cluster.id} is encrypted in transit."
                )

            findings.append(report)

        return findings

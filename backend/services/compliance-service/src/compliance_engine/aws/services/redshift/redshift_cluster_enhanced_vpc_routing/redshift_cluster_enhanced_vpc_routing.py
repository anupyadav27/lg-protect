from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.redshift.redshift_client import redshift_client


class redshift_cluster_enhanced_vpc_routing(Check):
    def execute(self):
        findings = []
        for cluster in redshift_client.clusters:
            report = Check_Report_AWS(metadata=self.metadata(), resource=cluster)
            report.status = "FAIL"
            report.status_extended = f"Redshift Cluster {cluster.id} does not have Enhanced VPC Routing security feature enabled."
            if cluster.enhanced_vpc_routing:
                report.status = "PASS"
                report.status_extended = f"Redshift Cluster {cluster.id} has Enhanced VPC Routing security feature enabled."

            findings.append(report)

        return findings

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.rds.rds_client import rds_client


class rds_instance_default_admin(Check):
    def execute(self):
        findings = []
        for db_instance in rds_client.db_instances.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=db_instance)
            # Check if is member of a cluster
            if db_instance.cluster_id:
                if (
                    db_instance.cluster_arn in rds_client.db_clusters
                    and rds_client.db_clusters[db_instance.cluster_arn].username
                    not in ["admin", "postgres"]
                ):
                    report.status = "PASS"
                    report.status_extended = f"RDS Instance {db_instance.id} is not using the default master username at cluster {db_instance.cluster_id} level."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"RDS Instance {db_instance.id} is using the default master username at cluster {db_instance.cluster_id} level."
            else:
                if db_instance.username not in ["admin", "postgres"]:
                    report.status = "PASS"
                    report.status_extended = f"RDS Instance {db_instance.id} is not using the default master username."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"RDS Instance {db_instance.id} is using the default master username."

            findings.append(report)

        return findings

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.elasticache.elasticache_client import (
    elasticache_client,
)


class elasticache_redis_cluster_automatic_failover_enabled(Check):
    def execute(self):
        findings = []
        for repl_group in elasticache_client.replication_groups.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=repl_group)
            report.status = "FAIL"
            report.status_extended = f"Elasticache Redis cache cluster {repl_group.id} does not have automatic failover enabled."

            if repl_group.automatic_failover == "enabled":
                report.status = "PASS"
                report.status_extended = f"Elasticache Redis cache cluster {repl_group.id} does have automatic failover enabled."

            findings.append(report)

        return findings
